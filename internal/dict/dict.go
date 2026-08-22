// Package dict loads domain-prefix dictionary files.
package dict

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Load reads prefix lines from path. Blank lines are skipped, prefixes are
// trimmed and lower-cased (domain names are case-insensitive), and duplicates
// keep their first position only.
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
		p := strings.ToLower(strings.TrimSpace(sc.Text()))
		if p == "" {
			continue
		}
		if strings.ContainsAny(p, " \t/\\") {
			return nil, fmt.Errorf("%s:%d: invalid prefix %q", path, lineNo, p)
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
