package dict

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeDict(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "d")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestReaderMatchesLoad walks every entry through the streaming Reader and
// compares it against the bulk loader — they must agree on what an entry is
// (modulo Load's dedup, exercised separately below).
func TestReaderMatchesLoad(t *testing.T) {
	cases := []struct {
		name string
		file string
	}{
		{"plain", "abc\nbcd\ncde\n"},
		{"no trailing newline", "abc\nbcd\ncde"},
		{"blank lines", "abc\n\n  \nbcd\n\ncde\n"},
		{"surrounding spaces", "  abc  \n\tBCD\t\n CDE \n"},
		{"windows newlines", "abc\r\nbcd\r\ncde\r\n"},
		{"empty", ""},
		{"only blanks", "\n\n  \n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeDict(t, tc.file)
			loaded, loadErr := Load(path)
			r := Open(path)
			defer r.Close()
			var streamed []string
			for i := 0; ; i++ {
				p, err := r.At(i)
				var short *shortfallError
				if errors.As(err, &short) {
					break // reached end of file
				}
				if err != nil {
					t.Fatalf("At(%d): %v", i, err)
				}
				streamed = append(streamed, p)
			}
			if loadErr != nil {
				if len(streamed) != 0 {
					t.Fatalf("Load failed (%v) but Reader streamed %d entries", loadErr, len(streamed))
				}
				return
			}
			// Load dedups; compare Reader against the deduped expectation.
			seen := map[string]bool{}
			var want []string
			for _, p := range loaded {
				if !seen[p] {
					seen[p] = true
					want = append(want, p)
				}
			}
			if len(streamed) != len(want) {
				t.Fatalf("streamed %d entries (%v), load-with-dedup wants %d (%v)",
					len(streamed), streamed, len(want), want)
			}
			for i := range want {
				if streamed[i] != want[i] {
					t.Fatalf("entry %d: streamed %q, load %q", i, streamed[i], want[i])
				}
			}
			if n, err := r.Count(); err != nil || n != len(want) {
				t.Fatalf("Count=%d err=%v, want %d", n, err, len(want))
			}
		})
	}
}

// TestReaderNoDedup pins the documented difference: duplicates surface as
// distinct entries, and both Reader and Load count them.
func TestReaderNoDedup(t *testing.T) {
	path := writeDict(t, "abc\nabc\nbcd\n")
	r := Open(path)
	defer r.Close()
	var got []string
	for i := 0; ; i++ {
		p, err := r.At(i)
		var short *shortfallError
		if errors.As(err, &short) {
			break // reached end of file
		}
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, p)
	}
	want := []string{"abc", "abc", "bcd"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("entry %d: got %q want %q", i, got[i], want[i])
		}
	}
}

// TestReaderRejectsInvalidPrefix: whitespace or path separators inside an
// entry fail the Reader the same way they fail Load.
func TestReaderRejectsInvalidPrefix(t *testing.T) {
	for _, bad := range []string{"a b\n", "a/b\n", "a\\b\n"} {
		path := writeDict(t, "ok\n"+bad)
		if _, err := Load(path); err == nil {
			t.Fatalf("Load should reject %q", bad)
		}
		r := Open(path)
		defer r.Close()
		if _, err := r.Count(); err == nil || !strings.Contains(err.Error(), "invalid prefix") {
			t.Fatalf("Reader should reject %q, got %v", bad, err)
		}
	}
}

// TestReaderBeyondEOF: asking for an index past the end reports how many
// entries the file actually has — the caller-facing signal for "dictionary
// changed since the task started".
func TestReaderBeyondEOF(t *testing.T) {
	path := writeDict(t, "abc\nbcd\n")
	r := Open(path)
	defer r.Close()
	_, err := r.At(2)
	var short *shortfallError
	if !errors.As(err, &short) || short.Count != 2 {
		t.Fatalf("At(2) on 2-entry dict: want shortfall{Count:2}, got %v", err)
	}
	// The reader stays usable for valid indices afterwards.
	if p, err := r.At(1); err != nil || p != "bcd" {
		t.Fatalf("At(1) after shortfall: %q %v", p, err)
	}
}

// TestReaderRewind: out-of-order access replays from the start, so a
// resumed scan can re-read a lower index correctly.
func TestReaderRewind(t *testing.T) {
	path := writeDict(t, "aa\nbb\ncc\ndd\n")
	r := Open(path)
	defer r.Close()
	if p, err := r.At(3); err != nil || p != "dd" {
		t.Fatalf("At(3): %q %v", p, err)
	}
	if p, err := r.At(0); err != nil || p != "aa" {
		t.Fatalf("rewind At(0): %q %v", p, err)
	}
	if p, err := r.At(2); err != nil || p != "cc" {
		t.Fatalf("replay At(2): %q %v", p, err)
	}
}

// TestReaderCaseFolding matches Load's normalization: uppercase in the
// dictionary becomes lowercase.
func TestReaderCaseFolding(t *testing.T) {
	path := writeDict(t, "ABC\nDeF\n")
	r := Open(path)
	defer r.Close()
	if p, err := r.At(0); err != nil || p != "abc" {
		t.Fatalf("At(0): %q %v", p, err)
	}
	if p, err := r.At(1); err != nil || p != "def" {
		t.Fatalf("At(1): %q %v", p, err)
	}
}

// TestOpenMissingFile surfaces the standard open error.
func TestOpenMissingFile(t *testing.T) {
	r := Open(filepath.Join(t.TempDir(), "nope"))
	defer r.Close()
	if _, err := r.Count(); err == nil {
		t.Fatal("missing file should error")
	}
}

// TestCountLeavesReaderAtZero pins the contract the scan loop relies on:
// after Count, At(0) returns the first entry without a re-open.
func TestCountLeavesReaderAtZero(t *testing.T) {
	path := writeDict(t, "a\nb\nc\n")
	r := Open(path)
	defer r.Close()
	if n, err := r.Count(); err != nil || n != 3 {
		t.Fatalf("Count: %d %v", n, err)
	}
	if p, err := r.At(0); err != nil || p != "a" {
		t.Fatalf("At(0) after Count: %q %v", p, err)
	}
}
