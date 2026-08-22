package app

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// maxDictEntries guards against absurd generation requests (e.g. 40
// characters with length 20). Beyond this the request is rejected instead of
// filling the disk.
const maxDictEntries = 50_000_000 // ~500 MB of text

// warnDictEntries above this the generator prints an estimated-size notice.
const warnDictEntries = 1_000_000

// generateDict writes every wordLen-length combination of charset into
// <dataDir>/dict/<outName>, creating the directory when needed. The output
// file must not already exist: generated dictionaries must never silently
// clobber a curated one.
func generateDict(opts Options, printf, eprintf func(string, ...any)) error {
	chars := dedupeRunes(opts.Charset)
	if len(chars) == 0 {
		return errors.New("-charset must contain at least one usable character")
	}
	if opts.WordLen <= 0 {
		return errors.New("-len must be >= 1")
	}
	if opts.OutName == "" {
		return errors.New("-out is required (output file name inside dict/)")
	}
	if strings.ContainsAny(opts.OutName, "/\\") || opts.OutName == "." || opts.OutName == ".." {
		return fmt.Errorf("-out must be a plain file name, got %q", opts.OutName)
	}

	total, ok := powU64(uint64(len(chars)), uint64(opts.WordLen))
	if !ok || total > maxDictEntries {
		return fmt.Errorf("charset %d ^ len %d exceeds the %d entry limit; shrink -charset or -len",
			len(chars), opts.WordLen, maxDictEntries)
	}
	if total > warnDictEntries {
		eprintf("[!] %d entries will be generated (~%d MB); this may take a while.",
			total, total*uint64(wordBytesHint(chars, opts.WordLen))/1024/1024)
	}

	dictDir := filepath.Join(opts.DataDir, "dict")
	if err := os.MkdirAll(dictDir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dictDir, err)
	}
	outPath := filepath.Join(dictDir, opts.OutName)
	if _, err := os.Stat(outPath); err == nil {
		return fmt.Errorf("%s already exists; choose another -out name", outPath)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat %s: %w", outPath, err)
	}

	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("create %s: %w", outPath, err)
	}
	w := bufio.NewWriterSize(f, 1<<20)

	buf := make([]rune, opts.WordLen)
	idx := make([]int, opts.WordLen)
	for pos := range idx { // first word: all first characters
		idx[pos] = 0
		buf[pos] = chars[0]
	}

	var written uint64
	line := make([]byte, 0, opts.WordLen*4+1)
	for {
		line = line[:0]
		for _, r := range buf {
			line = append(line, string(r)...)
		}
		line = append(line, '\n')
		if _, err := w.Write(line); err != nil {
			f.Close()
			return fmt.Errorf("write %s: %w", outPath, err)
		}
		written++

		if !nextWord(idx, len(chars)) {
			break
		}
		for pos := range idx {
			buf[pos] = chars[idx[pos]]
		}
	}

	if err := w.Flush(); err != nil {
		f.Close()
		return fmt.Errorf("flush %s: %w", outPath, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("sync %s: %w", outPath, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", outPath, err)
	}

	fi, _ := os.Stat(outPath)
	printf("Dictionary generated: %s", outPath)
	printf("Entries: %d (charset %d chars x len %d), size: %d bytes",
		written, len(chars), opts.WordLen, fiSize(fi))
	return nil
}

// nextWord advances the mixed-radix odometer; returns false after the last
// combination.
func nextWord(idx []int, base int) bool {
	for pos := len(idx) - 1; pos >= 0; pos-- {
		idx[pos]++
		if idx[pos] < base {
			return true
		}
		idx[pos] = 0
	}
	return false
}

func dedupeRunes(s string) []rune {
	seen := make(map[rune]bool)
	var out []rune
	for _, r := range s {
		r = trimSpaceRune(r)
		if r == 0 || seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	return out
}

func trimSpaceRune(r rune) rune {
	switch r {
	case ' ', '\t', '\n', '\r':
		return 0
	}
	return r
}

func powU64(base, exp uint64) (uint64, bool) {
	if exp == 0 {
		return 1, true
	}
	var result uint64 = 1
	for i := uint64(0); i < exp; i++ {
		if result > (1<<62)/base { // overflow guard with headroom
			return 0, false
		}
		result *= base
	}
	return result, true
}

func fiSize(fi os.FileInfo) int64 {
	if fi == nil {
		return 0
	}
	return fi.Size()
}

func wordBytesHint(chars []rune, wordLen int) int {
	n := 0
	for _, r := range chars {
		n += len(string(r))
	}
	avg := n / len(chars)
	if avg < 1 {
		avg = 1
	}
	return avg*wordLen + 1
}
