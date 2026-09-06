// Package dict loads and streams domain-prefix dictionary files.
package dict

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Load reads prefix lines from path. Blank lines are skipped, prefixes are
// trimmed and lower-cased (domain names are case-insensitive), and duplicates
// keep their first position only.
//
// Memory: O(dictionary). Fine for curated word lists; for generated
// dictionaries with millions of entries use Open instead, which streams.
func Load(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	defer f.Close()

	var out []string
	seen := make(map[string]bool)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024) // tolerate long lines
	lineNo := 0
	for sc.Scan() {
		lineNo++
		p := normalize(sc.Text())
		if p == "" {
			continue
		}
		if p == invalidPrefix {
			return nil, fmt.Errorf("%s:%d: invalid prefix %q", path, lineNo, sc.Text())
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: dictionary is empty", path)
	}
	return out, nil
}

// Reader streams a dictionary file entry by entry. It exposes the same
// normalization rules as Load (trim, lowercase, blank lines skipped,
// same validation) but keeps only one line in memory, so scanning a
// multi-million-entry generated dictionary costs O(1) memory instead of
// holding every prefix on the heap.
//
// Unlike Load it does NOT deduplicate: duplicate lines are surfaced as
// distinct entries. That is also why Load and a Reader over the same file
// may disagree on total count; tasks must pick one scheme and stick to it.
//
// An index beyond EOF is reported as an error rather than a missing entry,
// so callers can detect a dictionary that changed since the task started.
type Reader struct {
	path string
	f    *os.File
	r    *bufio.Reader
	n    int  // number of valid entries returned so far
	eof  bool // no further entries in the file
}

// Open prepares a Reader over path. The file is opened lazily on first read
// so Open itself never does I/O on behalf of inspection-only callers.
func Open(path string) *Reader { return &Reader{path: path} }

// Count streams the file once and returns the number of valid entries.
// It leaves the Reader positioned at entry 0, ready for At calls.
func (r *Reader) Count() (int, error) {
	if err := r.reset(); err != nil {
		return 0, err
	}
	for {
		if _, err := r.At(r.n); err != nil {
			var short *shortfallError
			if errors.As(err, &short) {
				return r.n, nil
			}
			return r.n, err
		}
	}
}

// shortfallError reports a dictionary shorter than the index demanded;
// r.n() through its Count field is the number of valid entries present.
type shortfallError struct {
	Count int
	Index int
	Path  string
}

func (e *shortfallError) Error() string {
	return fmt.Sprintf("dict: %s has only %d entries, need index %d", e.Path, e.Count, e.Index)
}

// At returns entry i, reading forward from the current position. It is
// meant for strictly increasing i (the scan loop's access pattern); going
// backwards rewinds by re-reading from the start, O(N) in the worst case,
// which keeps the implementation trivially correct instead of tracking
// offsets in memory.
func (r *Reader) At(i int) (string, error) {
	if i < 0 {
		return "", fmt.Errorf("dict: index %d out of range", i)
	}
	if r.f == nil {
		if err := r.reset(); err != nil {
			return "", err
		}
	}
	if i < r.n {
		// Rewind and replay. Cheap for the few-index jump of a resume and
		// the hot path (forward scan) is unaffected.
		if err := r.reset(); err != nil {
			return "", err
		}
	}
	for r.n <= i {
		line, err := r.readLine()
		if err != nil {
			if err == io.EOF {
				// Reaching EOF while entry i is still outstanding means the
				// file ended before index i (i > last index). Surface how
				// many entries exist so the caller can compare with its
				// recorded total.
				return "", &shortfallError{Count: r.n, Index: i, Path: r.path}
			}
			return "", err
		}
		p := normalize(line)
		if p == invalidPrefix {
			return "", fmt.Errorf("dict: %s: invalid prefix %q at line %d", r.path, line, r.n+1)
		}
		if p == "" {
			continue // blank line: not an entry
		}
		r.n++
		if r.n == i+1 {
			return p, nil
		}
	}
	// unreachable: loop above returns for r.n == i+1
	return "", fmt.Errorf("dict: unreachable state")
}

// Close releases the underlying file handle. Safe on a never-read Reader.
func (r *Reader) Close() error {
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f, r.r = nil, nil
	return err
}

// reset (re)opens the file and clears position state.
func (r *Reader) reset() error {
	r.Close()
	f, err := os.Open(r.path)
	if err != nil {
		return fmt.Errorf("dict: open %s: %w", r.path, err)
	}
	r.f = f
	r.r = bufio.NewReaderSize(f, 64*1024)
	r.n = 0
	r.eof = false
	return nil
}

// readLine returns the next physical line without its terminator; io.EOF at
// end of file. A final line without a trailing newline is still returned.
func (r *Reader) readLine() (string, error) {
	if r.eof {
		return "", io.EOF
	}
	line, err := r.r.ReadString('\n')
	switch {
	case err == io.EOF:
		r.eof = true
		if line == "" {
			return "", io.EOF
		}
		return line, nil
	case err != nil:
		return "", fmt.Errorf("dict: read %s: %w", r.path, err)
	}
	return strings.TrimSuffix(line, "\n"), nil
}

// invalidPrefix marks a line that fails validation; normalize never returns
// it for a usable entry.
const invalidPrefix = "\x00invalid"

// normalize applies the shared entry rules: trim, lowercase, reject
// whitespace/path separators. Blank lines become "". Used by both Load and
// Reader so the two paths always agree on what an entry is.
func normalize(line string) string {
	p := strings.ToLower(strings.TrimSpace(line))
	if p == "" {
		return ""
	}
	if strings.ContainsAny(p, " \t/\\") {
		return invalidPrefix
	}
	return p
}

// Path returns the conventional dictionary location inside dataDir.
func Path(dataDir, name string) string { return filepath.Join(dataDir, "dict", name) }

// List returns the dictionary file names available in dataDir/dict.
func List(dataDir string) []string {
	entries, err := os.ReadDir(filepath.Join(dataDir, "dict"))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.Type().IsRegular() {
			out = append(out, e.Name())
		}
	}
	return out
}
