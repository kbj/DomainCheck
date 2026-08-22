// Package config loads the TLD registry (tld.json) that maps a
// top-level domain to its WHOIS server and the response marker that
// identifies an unregistered (available) domain.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Entry describes one TLD.
type Entry struct {
	NIC      string `json:"nic"`      // WHOIS server host, e.g. whois.nic.xyz
	Response string `json:"response"` // marker in the response of an unregistered domain
}

// Registry is the parsed tld.json content.
type Registry struct {
	byTLD  map[string]Entry
	Source string // path the registry was loaded from
}

type rawFile map[string]struct {
	Nic      string `json:"nic"`
	Response string `json:"response"`
}

// Load reads and validates the registry file at path.
func Load(path string) (*Registry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var raw rawFile
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("%s contains no TLD entries", path)
	}
	reg := &Registry{byTLD: make(map[string]Entry, len(raw)), Source: path}
	for tld, e := range raw {
		tld = strings.ToLower(strings.TrimSpace(tld))
		e.Nic = strings.TrimSpace(e.Nic)
		e.Response = strings.TrimSpace(e.Response)
		if e.Nic == "" || e.Response == "" {
			return nil, fmt.Errorf("%s: entry %q is missing \"nic\" or \"response\"", path, tld)
		}
		reg.byTLD[tld] = Entry{NIC: e.Nic, Response: e.Response}
	}
	return reg, nil
}

// DefaultPath returns the conventional registry location inside dataDir.
func DefaultPath(dataDir string) string { return filepath.Join(dataDir, "tld.json") }

// Lookup returns the entry for tld (case-insensitive). Unknown TLDs yield an
// error that lists the available ones.
func (r *Registry) Lookup(tld string) (Entry, error) {
	e, ok := r.byTLD[strings.ToLower(strings.TrimSpace(tld))]
	if !ok {
		return Entry{}, fmt.Errorf("TLD %q not found in %s; available: %s",
			tld, filepath.Base(r.Source), strings.Join(r.TLDs(), ", "))
	}
	return e, nil
}

// TLDs returns all registered TLDs sorted alphabetically.
func (r *Registry) TLDs() []string {
	out := make([]string, 0, len(r.byTLD))
	for t := range r.byTLD {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
