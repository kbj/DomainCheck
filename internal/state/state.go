// Package state implements crash-safe persistence for a scan task.
//
// Design (v2), built to scale to dictionaries with millions of entries:
//
//   - The metadata file (*.state.json) holds only the task configuration and
//     a tiny amount of progress bookkeeping: a "progress" watermark plus the
//     sparse set of failed indices. Its size is O(#failures), typically a few
//     hundred bytes regardless of dictionary size. It is rewritten atomically
//     (temp file + rename) after every domain.
//   - The journal file (*.journal) is append-only: one line per checked
//     domain with its outcome. Appending is O(1) and preserves the full
//     history for auditing without ever holding it in memory.
//
// Progress invariant at rest:
//
//	every index i < Progress has a conclusive record in the journal
//	(available / unavailable / failed); exactly the Failed members are
//	not conclusive.
//
// The resume cursor is therefore min(Failed[0].Index, Progress).
//
// Memory usage is O(1) w.r.t. dictionary size (plus the O(#failures) list);
// only the caller's own prefix slice scales with the dictionary.
package state

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Status is the outcome of a single domain query.
type Status string

const (
	// Authoritative results obtained from the WHOIS server.
	StatusPending     Status = "pending" // not checked yet (implicit; never persisted per-domain)
	StatusAvailable   Status = "available"
	StatusUnavailable Status = "unavailable"
	StatusFailed      Status = "failed" // retries exhausted; retried on resume

	// DNS-derived results (less authoritative):
	//   unavailable-dns: NS records exist -> definitely registered;
	//   available-dns:   no NS records -> PROBABLY available, but registered
	//                    yet undelegated domains look the same.
	StatusUnavailableDNS Status = "unavailable-dns"
	StatusAvailableDNS   Status = "available-dns"
)

const currentVersion = 2

// Definitive reports whether s is a final answer that does not need to be
// re-checked on resume.
func (s Status) Definitive() bool {
	return s == StatusAvailable || s == StatusUnavailable ||
		s == StatusAvailableDNS || s == StatusUnavailableDNS
}

// FailedEntry records a domain whose queries kept failing.
type FailedEntry struct {
	Index    int       `json:"index"`
	Domain   string    `json:"domain"`
	Attempts int       `json:"attempts"`
	Error    string    `json:"error"`
	At       time.Time `json:"at"`
}

// Task is the persistent state of one scan. Everything except Failed scales
// O(1) with dictionary size.
type Task struct {
	Version      int    `json:"version"` // state format version, currently 2
	TLD          string `json:"tld"`
	DictName     string `json:"dict"`
	DictPath     string `json:"dict_path"` // where prefixes are reloaded from on resume
	NIC          string `json:"nic"`       // WHOIS server host
	ResponseMark string `json:"response_marker"`
	DelaySeconds int    `json:"delay_seconds"`
	LogPath      string `json:"log_path"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	Total         int           `json:"total"`          // number of dict entries
	Progress      int           `json:"progress"`       // see package doc invariant
	Failed        []FailedEntry `json:"failed"`         // sorted by Index; subset of [0,Progress)
	HeaderWritten bool          `json:"header_written"` // log header already emitted

	// WhoisDisabled marks a task that judges domains purely by DNS NS
	// records: either the TLD has no WHOIS configuration at all, or the
	// server's anti-crawl defenses exhausted the retry budget mid-run.
	WhoisDisabled bool `json:"whois_disabled,omitempty"`

	metaPath    string
	journalPath string
	journal     *bufio.Writer
	journalF    *os.File
}

// Config carries the immutable task description used by New.
type Config struct {
	TLD, DictName, DictPath string
	NIC, ResponseMark       string
	DelaySeconds            int
	LogPath, StatePath      string
	JournalPath             string
	Total                   int
}

// New creates a v2 task (metadata + empty journal) and persists it.
func New(cfg Config) (*Task, error) {
	now := time.Now()
	t := &Task{
		Version:      currentVersion,
		TLD:          cfg.TLD,
		DictName:     cfg.DictName,
		DictPath:     cfg.DictPath,
		NIC:          cfg.NIC,
		ResponseMark: cfg.ResponseMark,
		DelaySeconds: cfg.DelaySeconds,
		LogPath:      cfg.LogPath,
		CreatedAt:    now,
		UpdatedAt:    now,
		Total:        cfg.Total,
		metaPath:     cfg.StatePath,
		journalPath:  cfg.JournalPath,
	}
	if err := t.openJournal(false); err != nil {
		return nil, err
	}
	if err := t.SaveMeta(); err != nil {
		return nil, err
	}
	return t, nil
}

// BeginSession computes the resume cursor and prepares skip information so
// the scan loop re-checks only domains that lack a conclusive result.
//
// It streams the journal once to mark which indices in [cursor, Progress)
// are already settled (those get skipped); typical region size is small.
// The returned Session holds that temporary map; memory is O(region), not
// O(dictionary).
func (t *Task) BeginSession() (*Session, error) {
	if err := t.journalFlush(); err != nil {
		return nil, err
	}
	start := t.Cursor()
	s := &Session{Start: start}
	if t.Progress > start {
		s.Settled = make([]byte, t.Progress-start)
		f, err := os.Open(t.journalPath)
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("state: open journal %s: %w", t.journalPath, err)
		}
		if f != nil {
			defer f.Close()
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
			for sc.Scan() {
				idx, st, ok := parseJournalLine(sc.Text())
				if ok && st.Definitive() && idx >= start && idx < t.Progress {
					s.Settled[idx-start] = 1
				}
			}
			if err := sc.Err(); err != nil {
				return nil, fmt.Errorf("state: read journal %s: %w", t.journalPath, err)
			}
		}
	}
	return s, nil
}

// Session describes where and how a scan iteration should proceed.
type Session struct {
	// Start is the first index to examine.
	Start int
	// Settled[i-Start] == 1 means index i already has a definitive result
	// and must be skipped. Only covers [Start, Progress).
	Settled []byte
}

// ShouldSkip reports whether index i needs no further query.
func (s *Session) ShouldSkip(i int) bool {
	j := i - s.Start
	return j >= 0 && j < len(s.Settled) && s.Settled[j] == 1
}

// Record persists one domain outcome: appended to the journal (O(1)) and
// folded into the in-memory bookkeeping. Call SaveMeta afterwards to make
// the progress durable. domain is the queried name (used for failure records).
//
// Definitive results must arrive sequentially at the frontier (idx ==
// Progress, the normal flow) or below it (a previously failed index being
// retried); anything beyond the frontier is an ordering bug and rejected.
func (t *Task) Record(idx int, domain string, status Status, errMsg string, attempts int) error {
	if idx < 0 || idx >= t.Total {
		return fmt.Errorf("state: index %d out of range [0,%d)", idx, t.Total)
	}
	if err := t.writeJournal(idx, status, errMsg, attempts); err != nil {
		return err
	}
	switch status {
	case StatusAvailable, StatusUnavailable, StatusAvailableDNS, StatusUnavailableDNS:
		if idx > t.Progress {
			return fmt.Errorf("state: non-sequential definitive record %d (progress=%d)", idx, t.Progress)
		}
		if idx < t.Progress && !t.inFailed(idx) {
			return fmt.Errorf("state: duplicate conclusive record %d", idx)
		}
		t.removeFailed(idx)
		if idx == t.Progress {
			t.Progress++
		}
	case StatusFailed:
		if idx > t.Progress {
			return fmt.Errorf("state: non-sequential failed record %d (progress=%d)", idx, t.Progress)
		}
		t.upsertFailed(FailedEntry{
			Index:    idx,
			Domain:   domain,
			Attempts: attempts,
			Error:    errMsg,
			At:       time.Now(),
		})
		if idx == t.Progress {
			t.Progress++ // frontier moved past the failure; it stays in Failed
		}
	default:
		return fmt.Errorf("state: unexpected status %q", status)
	}
	t.touch()
	return nil
}

// SaveMeta flushes the journal buffer and atomically rewrites the metadata
// file (a few hundred bytes, independent of dictionary size).
func (t *Task) SaveMeta() error {
	t.touch()
	if err := t.journalFlush(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return fmt.Errorf("state: encode meta: %w", err)
	}
	data = append(data, '\n')
	return atomicWrite(t.metaPath, data)
}

// CloseJournal releases the journal file handle. Idempotent.
func (t *Task) CloseJournal() {
	if t.journal != nil {
		t.journal.Flush()
		t.journal = nil
	}
	if t.journalF != nil {
		t.journalF.Close()
		t.journalF = nil
	}
}

// Cursor is the index a fresh session would resume from: the first index
// without a conclusive result.
func (t *Task) Cursor() int {
	if len(t.Failed) > 0 && t.Failed[0].Index < t.Progress {
		return t.Failed[0].Index
	}
	return t.Progress
}

// MetaPath returns the metadata file path this task was loaded from / saved to.
func (t *Task) MetaPath() string { return t.metaPath }

// JournalPath returns the append-only journal file path.
func (t *Task) JournalPath() string { return t.journalPath }

// Done reports whether every domain has been conclusively checked.
func (t *Task) Done() bool { return t.Progress >= t.Total && len(t.Failed) == 0 }

// Counts tallies outcomes. Available/unavailable come from streaming the
// journal (O(1) memory); pending is derived.
type Counts struct {
	Available      int
	Unavailable    int
	AvailableDNS   int // uncertain: no NS records seen
	UnavailableDNS int // certain: NS records exist
	Failed         int
	Pending        int
	Checked        int // every definitive outcome combined
}

// Counts streams the journal to compute exact per-status tallies using one
// byte of memory per dictionary entry (e.g. ~1 MB for a million domains).
func (t *Task) Counts() (Counts, error) {
	c := Counts{Failed: len(t.Failed)}
	if err := t.journalFlush(); err != nil {
		return c, err
	}
	f, err := os.Open(t.journalPath)
	if err != nil {
		if os.IsNotExist(err) {
			c.Pending = t.Total
			return c, nil
		}
		return c, err
	}
	defer f.Close()

	const (
		stUnknown = iota
		stAvailable
		stUnavailable
		stAvailableDNS
		stUnavailableDNS
	)
	status := make([]byte, t.Total)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		idx, st, ok := parseJournalLine(sc.Text())
		if !ok || idx >= t.Total {
			continue
		}
		switch st {
		case StatusAvailable:
			status[idx] = stAvailable // last line wins
		case StatusUnavailable:
			status[idx] = stUnavailable
		case StatusAvailableDNS:
			status[idx] = stAvailableDNS
		case StatusUnavailableDNS:
			status[idx] = stUnavailableDNS
		}
	}
	if err := sc.Err(); err != nil {
		return c, fmt.Errorf("state: read journal %s: %w", t.journalPath, err)
	}
	for _, st := range status {
		switch st {
		case stAvailable:
			c.Available++
		case stUnavailable:
			c.Unavailable++
		case stAvailableDNS:
			c.AvailableDNS++
		case stUnavailableDNS:
			c.UnavailableDNS++
		}
	}
	c.Checked = c.Available + c.Unavailable + c.AvailableDNS + c.UnavailableDNS
	c.Pending = t.Total - c.Checked - c.Failed
	if c.Pending < 0 { // defensive: should not happen
		c.Pending = 0
	}
	return c, nil
}

// ---- persistence helpers ----

func (t *Task) touch() { t.UpdatedAt = time.Now() }

func (t *Task) journalFlush() error {
	if t.journal != nil {
		if err := t.journal.Flush(); err != nil {
			return fmt.Errorf("state: flush journal: %w", err)
		}
	}
	return nil
}

func (t *Task) openJournal(appendMode bool) error {
	f, err := os.OpenFile(t.journalPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("state: open journal %s: %w", t.journalPath, err)
	}
	t.journalF = f
	t.journal = bufio.NewWriter(f)
	return nil
}

func (t *Task) writeJournal(idx int, status Status, errMsg string, attempts int) error {
	if t.journal == nil {
		if err := t.openJournal(true); err != nil {
			return err
		}
	}
	line := fmt.Sprintf("%d\t%s\t%d\t%d\t%s\n",
		idx, status, attempts, time.Now().UnixNano(), sanitizeField(errMsg))
	if _, err := t.journal.WriteString(line); err != nil {
		return fmt.Errorf("state: write journal: %w", err)
	}
	return nil
}

func (t *Task) upsertFailed(e FailedEntry) {
	for i := range t.Failed {
		if t.Failed[i].Index == e.Index {
			t.Failed[i] = e
			return
		}
	}
	t.Failed = append(t.Failed, e)
	sort.Slice(t.Failed, func(i, j int) bool { return t.Failed[i].Index < t.Failed[j].Index })
}

func (t *Task) removeFailed(idx int) {
	for i := range t.Failed {
		if t.Failed[i].Index == idx {
			t.Failed = append(t.Failed[:i], t.Failed[i+1:]...)
			return
		}
	}
}

func (t *Task) inFailed(idx int) bool {
	for i := range t.Failed {
		if t.Failed[i].Index == idx {
			return true
		}
	}
	return false
}

func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("state: create temp in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once rename succeeded

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("state: write %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("state: sync %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("state: close %s: %w", tmpName, err)
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return fmt.Errorf("state: chmod %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("state: rename -> %s: %w", path, err)
	}
	if d, err := os.Open(dir); err == nil { // best effort dir fsync
		d.Sync()
		d.Close()
	}
	return nil
}

// ---- loading & migration ----

// Load reads a task's metadata. v2 files load directly; legacy v1 files
// (which embedded every result) are migrated once to the v2 meta+journal
// format.
func Load(path string) (*Task, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("state: read %s: %w", path, err)
	}
	var probe struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("state: parse %s: %w", path, err)
	}
	switch probe.Version {
	case currentVersion:
		return loadV2(path, data)
	case 1:
		return migrateV1(path, data)
	default:
		return nil, fmt.Errorf("state: %s: unsupported version %d", path, probe.Version)
	}
}

func loadV2(path string, data []byte) (*Task, error) {
	var t Task
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("state: parse %s: %w", path, err)
	}
	if t.Total <= 0 {
		return nil, fmt.Errorf("state: %s: invalid total %d", path, t.Total)
	}
	if t.Progress > t.Total {
		return nil, fmt.Errorf("state: %s: progress %d exceeds total %d", path, t.Progress, t.Total)
	}
	sort.Slice(t.Failed, func(i, j int) bool { return t.Failed[i].Index < t.Failed[j].Index })
	t.metaPath = path
	base := strings.TrimSuffix(path, ".state.json")
	if t.journalPath == "" {
		t.journalPath = base + ".journal"
	}
	if err := t.openJournal(true); err != nil {
		return nil, err
	}
	return &t, nil
}

// migrateV1 converts an old single-file state (every result embedded) into
// the v2 meta+journal pair. Runs once, O(N).
func migrateV1(path string, data []byte) (*Task, error) {
	type v1Entry struct {
		Domain    string    `json:"domain"`
		Status    Status    `json:"status"`
		Error     string    `json:"error,omitempty"`
		Attempts  int       `json:"attempts,omitempty"`
		CheckedAt time.Time `json:"checked_at,omitempty"`
	}
	type v1Task struct {
		Version      int       `json:"version"`
		TLD          string    `json:"tld"`
		DictName     string    `json:"dict"`
		NIC          string    `json:"nic"`
		ResponseMark string    `json:"response_marker"`
		DelaySeconds int       `json:"delay_seconds"`
		LogPath      string    `json:"log_path"`
		CreatedAt    time.Time `json:"created_at"`
		UpdatedAt    time.Time `json:"updated_at"`
		Prefixes     []string  `json:"prefixes"`
		Results      []v1Entry `json:"results"`
		Cursor       int       `json:"cursor"`
	}
	var old v1Task
	if err := json.Unmarshal(data, &old); err != nil {
		return nil, fmt.Errorf("state: migrate %s: %w", path, err)
	}
	if len(old.Prefixes) == 0 || len(old.Prefixes) != len(old.Results) {
		return nil, fmt.Errorf("state: migrate %s: inconsistent v1 payload", path)
	}

	t := &Task{
		Version:       currentVersion,
		TLD:           old.TLD,
		DictName:      old.DictName,
		NIC:           old.NIC,
		ResponseMark:  old.ResponseMark,
		DelaySeconds:  old.DelaySeconds,
		LogPath:       old.LogPath,
		CreatedAt:     old.CreatedAt,
		UpdatedAt:     time.Now(),
		Total:         len(old.Prefixes),
		metaPath:      path,
		journalPath:   strings.TrimSuffix(path, ".state.json") + ".journal",
		HeaderWritten: true,
	}
	if err := t.openJournal(false); err != nil {
		return nil, err
	}
	// Replay every known result into the journal, then derive Progress/Failed.
	// Mirrors Record's rules: both definitive and failed entries advance the
	// frontier; only definitive ones leave the failed set.
	highWater := 0
	for i, r := range old.Results {
		st := r.Status
		if !st.Definitive() && st != StatusFailed {
			continue // pending: leave unexamined
		}
		attempts := r.Attempts
		if attempts == 0 {
			attempts = 1
		}
		if err := t.writeJournal(i, st, r.Error, attempts); err != nil {
			return nil, err
		}
		switch {
		case st.Definitive():
			t.removeFailed(i)
			if i+1 > highWater {
				highWater = i + 1
			}
		case st == StatusFailed:
			t.upsertFailed(FailedEntry{Index: i, Domain: r.Domain, Attempts: attempts, Error: r.Error, At: r.CheckedAt})
			if i+1 > highWater {
				highWater = i + 1
			}
		}
	}
	t.Progress = highWater
	if err := t.SaveMeta(); err != nil {
		return nil, err
	}
	return t, nil
}

// Resumable scans dir for *.state.json files that are not finished yet and
// returns their paths plus tasks, newest activity first.
func Resumable(dir string) ([]string, []*Task, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.state.json"))
	if err != nil {
		return nil, nil, err
	}
	type item struct {
		path string
		task *Task
	}
	var items []item
	for _, p := range matches {
		t, err := Load(p)
		if err != nil {
			continue // unreadable/corrupt files are skipped, never fatal
		}
		if !t.Done() {
			items = append(items, item{p, t})
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].task.UpdatedAt.After(items[j].task.UpdatedAt) })
	paths := make([]string, len(items))
	tasks := make([]*Task, len(items))
	for i, it := range items {
		paths[i], tasks[i] = it.path, it.task
	}
	return paths, tasks, nil
}

// StatePath builds the conventional metadata file path for a task started at
// startTime inside dir: <tld>_<dict>_<timestamp>.state.json.
func StatePath(dir, tld, dictName string, startTime time.Time) string {
	name := fmt.Sprintf("%s_%s_%s.state.json", tld, dictName, startTime.Format("2006-01-02-15-04-05"))
	return filepath.Join(dir, sanitize(name))
}

// LogPath mirrors the naming scheme of the original Python tool:
// <tld>_<dict>_<timestamp>.log
func LogPath(dir, tld, dictName string, startTime time.Time) string {
	name := fmt.Sprintf("%s_%s_%s.log", tld, dictName, startTime.Format("2006-01-02-15-04-05"))
	return filepath.Join(dir, sanitize(name))
}

// JournalPath pairs with a state path: <...>.journal
func JournalPath(statePath string) string {
	return strings.TrimSuffix(statePath, ".state.json") + ".journal"
}

func sanitize(name string) string {
	r := strings.NewReplacer("/", "_", "\\", "_", "\x00", "_")
	return r.Replace(name)
}

func sanitizeField(s string) string {
	r := strings.NewReplacer("\t", " ", "\n", " ", "\r", " ")
	s = r.Replace(s)
	if len(s) > 500 {
		s = s[:500]
	}
	return s
}

// parseJournalLine parses "<idx>\t<status>\t<attempts>\t<unixNano>\t<error>".
func parseJournalLine(line string) (int, Status, bool) {
	parts := strings.SplitN(line, "\t", 5)
	if len(parts) < 2 {
		return 0, "", false
	}
	idx, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, "", false
	}
	return idx, Status(parts[1]), true
}
