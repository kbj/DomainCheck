// Package state implements crash-safe persistence for a scan task.
//
// Design (v3), built to scale to dictionaries with millions of entries:
//
//   - The metadata file (*.state.json) holds only the task configuration and
//     a tiny amount of progress bookkeeping: a settled-count summary plus
//     the sparse set of failed indices. Its size is O(#failures), typically
//     a few hundred bytes regardless of dictionary size. It is rewritten
//     atomically (temp file + rename) after every domain.
//   - The journal file (*.journal) is append-only: one line per checked
//     domain with its outcome. Appending is O(1) and preserves the full
//     history for auditing without ever holding it in memory.
//
// Progress invariant at rest:
//
//	every index i with Settled[i]==1 has a conclusive record in the journal
//	(available / unavailable / redemption / pending-delete / failed);
//	exactly the Failed members are not conclusive.
//
// The resume cursor is the first index with Settled[i]==0.
//
// v3 note: records no longer arrive strictly in dictionary order — the
// two-queue scan runs a DNS pre-check worker pool ahead of the serial
// WHOIS consumer, so verdicts (including failures) may be recorded out of
// order. The in-memory Settled bitmap marks conclusive outcomes per index;
// Progress is its popcount (definitive-only). The bitmap itself is NOT
// persisted — the journal is the authoritative history and Settled is
// rebuilt from it on Load, keeping the meta file O(#failures) small and
// making progress self-healing after a crash (whatever the journal holds
// is exactly what is settled).
//
// Memory usage of the persisted state is O(1) w.r.t. dictionary size (plus
// the O(#failures) list); the caller's prefix slice and the in-memory
// Settled bitmap scale with the dictionary (one byte per entry, same order
// as the status array Counts() already uses). Counts() is the one other
// exception: it streams the journal.
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
	"sync"
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

	// Expiry-phase results from the WHOIS server: the domain is still
	// registered (NOT available) but sitting in a deletion pipeline.
	//   redemption:      EPP redemptionPeriod — 30-day redemption grace period;
	//   pending-delete:  EPP pendingDelete — final 5 days before dropping.
	// Both are definitive (an expiry phase never reverts to available).
	StatusRedemption    Status = "redemption"
	StatusPendingDelete Status = "pending-delete"

	// DNS-derived results (less authoritative):
	//   unavailable-dns: NS records exist -> definitely registered;
	//   available-dns:   no NS records -> PROBABLY available, but registered
	//                    yet undelegated domains look the same.
	StatusUnavailableDNS Status = "unavailable-dns"
	StatusAvailableDNS   Status = "available-dns"
)

const currentVersion = 3

// Definitive reports whether s is a final answer that does not need to be
// re-checked on resume.
func (s Status) Definitive() bool {
	return s == StatusAvailable || s == StatusUnavailable ||
		s == StatusRedemption || s == StatusPendingDelete ||
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
	Version      int    `json:"version"` // state format version, currently 3
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
	Progress      int           `json:"progress"`       // definitively settled count (display summary)
	Failed        []FailedEntry `json:"failed"`         // sorted by Index; retryable
	HeaderWritten bool          `json:"header_written"` // log header already emitted

	// WhoisDisabled marks a task that judges domains purely by DNS NS
	// records: either the TLD has no WHOIS configuration at all, or the
	// server's anti-crawl defenses exhausted the retry budget mid-run.
	WhoisDisabled bool `json:"whois_disabled,omitempty"`

	// Settled is the in-memory per-index bitmap of definitive outcomes.
	// NOT persisted: rebuilt from the journal on Load (the journal is the
	// authoritative history, keeping the meta file O(#failures) small).
	// Mutated under settledMu by Record / migrations.
	Settled []byte `json:"-"`

	// settledMu guards Settled/Progress/Failed: DNS pre-check workers
	// record verdicts concurrently while the WHOIS consumer runs.
	settledMu   sync.Mutex
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
		Settled:      make([]byte, cfg.Total),
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
// The returned Session holds a fresh copy of the settled bitmap covering
// [Start, Total); memory is O(dictionary) — one byte per entry, same order
// as the status array Counts() already uses.
func (t *Task) BeginSession() (*Session, error) {
	if err := t.journalFlush(); err != nil {
		return nil, err
	}
	t.settledMu.Lock()
	// The bitmap may be sparse (DNS workers settle out of order), so the
	// resume start is the FIRST zero bit, not the settled count. Failed
	// indices are zeros too, so they get re-checked — the v2 semantics.
	start := len(t.Settled)
	for i, s := range t.Settled {
		if s == 0 {
			start = i
			break
		}
	}
	s := &Session{Start: start, Settled: make([]byte, len(t.Settled))}
	copy(s.Settled, t.Settled)
	t.settledMu.Unlock()
	return s, nil
}

// Session describes where and how a scan iteration should proceed.
type Session struct {
	// Start is the first index to examine.
	Start int
	// Settled is the per-index bitmap of definitive outcomes, indexed by
	// ABSOLUTE dictionary index (a copy of Task.Settled at BeginSession
	// time). Failed indices are 0 so resume re-checks them.
	Settled []byte
}

// ShouldSkip reports whether index i needs no further query. Absolute
// addressing: an index beyond the bitmap or below Start is not skippable.
func (s *Session) ShouldSkip(i int) bool {
	return i >= 0 && i < len(s.Settled) && s.Settled[i] == 1
}

// Record persists one domain outcome: appended to the journal (O(1)) and
// folded into the in-memory bookkeeping. Call SaveMeta afterwards to make
// the progress durable. domain is the queried name (used for failure records).
//
// Records may arrive out of order (the two-queue scan runs DNS pre-checks
// ahead of the serial WHOIS consumer), so there is no sequential-frontier
// check. Anything already settled is rejected as a duplicate — except a
// failed retry upserting its own earlier entry (Settled[i]==1 while the
// index still sits in Failed) or that retry later succeeding (failed →
// definitive upgrade).
func (t *Task) Record(idx int, domain string, status Status, errMsg string, attempts int) error {
	if idx < 0 || idx >= t.Total {
		return fmt.Errorf("state: index %d out of range [0,%d)", idx, t.Total)
	}
	t.settledMu.Lock()
	defer t.settledMu.Unlock()

	isFailed := status == StatusFailed
	if !isFailed && !status.Definitive() {
		return fmt.Errorf("state: unexpected status %q", status)
	}
	if t.Settled[idx] == 1 {
		// Definitively settled; recording over it is an ordering bug. The
		// failed→definitive upgrade path never lands here: Settled is only
		// set on definitive outcomes, and a retried failure's first
		// recording left it unset.
		return fmt.Errorf("state: duplicate conclusive record %d", idx)
	}
	if err := t.writeJournal(idx, status, errMsg, attempts); err != nil {
		return err
	}
	if isFailed {
		t.upsertFailed(FailedEntry{
			Index:    idx,
			Domain:   domain,
			Attempts: attempts,
			Error:    errMsg,
			At:       time.Now(),
		})
	} else {
		t.removeFailed(idx)
		t.Settled[idx] = 1
		t.Progress++ // settled count (order-independent)
	}
	t.touch()
	return nil
}

// SaveMeta flushes the journal buffer and atomically rewrites the metadata
// file (a few hundred bytes, independent of dictionary size). Safe for
// concurrent use: DNS pre-check workers and the WHOIS consumer both call
// it, so the journal flush and the meta snapshot are serialized.
func (t *Task) SaveMeta() error {
	t.settledMu.Lock()
	defer t.settledMu.Unlock()
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

// CheckedCount is the number of conclusively judged domains (definitively
// settled plus retryable failures) — the display counterpart of the
// resume start (the first zero bit of Settled).
func (t *Task) CheckedCount() int {
	t.settledMu.Lock()
	defer t.settledMu.Unlock()
	n := 0
	for _, s := range t.Settled {
		n += int(s)
	}
	return n + len(t.Failed)
}

// Cursor is the index a fresh session would resume from: the first index
// without a definitive result (the first zero of the Settled bitmap). A
// fully settled task yields Total. Failed indices are unsettled by design,
// so the cursor lands on them for re-checking.
func (t *Task) Cursor() int {
	t.settledMu.Lock()
	defer t.settledMu.Unlock()
	for i, s := range t.Settled {
		if s == 0 {
			return i
		}
	}
	return len(t.Settled)
}

// MetaPath returns the metadata file path this task was loaded from / saved to.
func (t *Task) MetaPath() string { return t.metaPath }

// JournalPath returns the append-only journal file path.
func (t *Task) JournalPath() string { return t.journalPath }

// Done reports whether every domain has been conclusively checked: the
// settled bitmap is full (no retryable failure outstanding) and no failure
// entry remains.
func (t *Task) Done() bool { return t.Progress == t.Total && len(t.Failed) == 0 }

// Counts tallies outcomes. Available/unavailable come from streaming the
// journal (O(1) memory); pending is derived.
type Counts struct {
	Available      int
	Unavailable    int
	Redemption     int // WHOIS says EPP redemptionPeriod (still registered)
	PendingDelete  int // WHOIS says EPP pendingDelete (about to drop)
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
		stRedemption
		stPendingDelete
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
		case StatusRedemption:
			status[idx] = stRedemption
		case StatusPendingDelete:
			status[idx] = stPendingDelete
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
		case stRedemption:
			c.Redemption++
		case stPendingDelete:
			c.PendingDelete++
		case stAvailableDNS:
			c.AvailableDNS++
		case stUnavailableDNS:
			c.UnavailableDNS++
		}
	}
	c.Checked = c.Available + c.Unavailable + c.Redemption + c.PendingDelete +
		c.AvailableDNS + c.UnavailableDNS
	c.Pending = t.Total - c.Checked - c.Failed
	if c.Pending < 0 { // defensive: should not happen
		c.Pending = 0
	}
	return c, nil
}

// recount recomputes Progress as the settled popcount. Caller must hold
// settledMu (migrations use it single-threaded before any concurrency).
func (t *Task) recount() {
	n := 0
	for _, s := range t.Settled {
		n += int(s)
	}
	t.Progress = n
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

// Load reads a task's metadata. v3 files load directly; v2 files (watermark
// Progress without a Settled bitmap) and legacy v1 files (which embedded
// every result) are migrated once to the current format.
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
		return loadV3(path, data)
	case 2:
		return migrateV2(path, data)
	case 1:
		return migrateV1(path, data)
	default:
		return nil, fmt.Errorf("state: %s: unsupported version %d", path, probe.Version)
	}
}

// loadV3 reads a v3 task and rebuilds the in-memory Settled bitmap from
// the journal (the authoritative history; see package doc).
func loadV3(path string, data []byte) (*Task, error) {
	t, err := loadV2(path, data)
	if err != nil {
		return nil, err
	}
	defer t.CloseJournal()
	t.Settled = make([]byte, t.Total)
	f, err := os.Open(t.journalPath)
	if err != nil {
		if os.IsNotExist(err) {
			return t, nil // fresh task: nothing settled yet
		}
		return nil, fmt.Errorf("state: %s: open journal: %w", path, err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		idx, st, ok := parseJournalLine(sc.Text())
		if ok && st.Definitive() && idx >= 0 && idx < t.Total {
			t.Settled[idx] = 1 // failed lines stay unsettled: re-checked on resume
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("state: %s: read journal: %w", path, err)
	}
	t.recount()
	return t, nil
}

// migrateV2 upgrades a v2 state (sequential-frontier Progress, no Settled
// bitmap) to v3. One pass, O(N): the journal replay marks definitively
// settled indices; failed entries stay unsettled so resume re-checks them
// (same semantics as v2's cursor). The old watermark is ignored — the
// replay is authoritative.
func migrateV2(path string, data []byte) (*Task, error) {
	return loadV3(path, data) // same rebuild; version field is rewritten below
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
	// Journal is opened lazily on first write (see writeJournal) so tasks
	// loaded only for inspection — Resumable / the resume menu — never hold
	// a file handle. BeginSession and Counts read the journal file directly
	// (os.Open) and journalFlush is nil-safe against a closed journal.
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
		Settled:       make([]byte, len(old.Prefixes)),
		metaPath:      path,
		journalPath:   strings.TrimSuffix(path, ".state.json") + ".journal",
		HeaderWritten: true,
	}
	if err := t.openJournal(false); err != nil {
		return nil, err
	}
	// Replay every known result into the journal, then derive Progress/Failed.
	// Mirrors Record's rules: definitive entries settle their index; failed
	// ones join the retry list but stay unsettled (re-checked on resume).
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
			t.Settled[i] = 1
			t.Progress++
		case st == StatusFailed:
			t.upsertFailed(FailedEntry{Index: i, Domain: r.Domain, Attempts: attempts, Error: r.Error, At: r.CheckedAt})
		}
	}
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

// ExpiringLogPath pairs with a result log path: <...>.expiring.log. It holds
// the expiry-phase verdicts (redemption / pending-delete) apart from the
// available-only main log.
func ExpiringLogPath(logPath string) string {
	return strings.TrimSuffix(logPath, ".log") + ".expiring.log"
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
