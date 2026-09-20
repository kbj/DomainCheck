package state

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// newTestTask creates a v2 task over 3 prefixes in a temp dir.
func newTestTask(t *testing.T) *Task {
	t.Helper()
	dir := t.TempDir()
	tk, err := New(Config{
		TLD: "xyz", DictName: "test", DictPath: filepath.Join(dir, "dict", "test"),
		NIC: "whois.nic.xyz", ResponseMark: "object does not exist",
		DelaySeconds: 0,
		LogPath:      filepath.Join(dir, "out.log"),
		StatePath:    filepath.Join(dir, "x_test_2026.state.json"),
		JournalPath:  filepath.Join(dir, "x_test_2026.journal"),
		Total:        3,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(tk.CloseJournal)
	return tk
}

func TestNewTaskFresh(t *testing.T) {
	tk := newTestTask(t)
	if tk.Progress != 0 || len(tk.Failed) != 0 || tk.HeaderWritten {
		t.Fatalf("bad init: progress=%d failed=%d header=%v", tk.Progress, len(tk.Failed), tk.HeaderWritten)
	}
	if tk.Cursor() != 0 {
		t.Fatalf("cursor=%d want 0", tk.Cursor())
	}
	if tk.Done() {
		t.Fatal("fresh task must not be done")
	}
}

func TestSequentialRecordingWithMidwayFailure(t *testing.T) {
	tk := newTestTask(t)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}

	must(tk.Record(0, "abc.xyz", StatusAvailable, "", 1))   // settled={0}, P=1
	must(tk.Record(1, "bcd.xyz", StatusFailed, "boom", 5))  // F={1}, stays unsettled
	must(tk.Record(2, "cde.xyz", StatusUnavailable, "", 1)) // settled={0,2}, P=2

	// Failed entries no longer advance Progress (v3): settled counts
	// definitive outcomes only, so the retryable failure stays unsettled.
	if tk.Progress != 2 || len(tk.Failed) != 1 || tk.Failed[0].Index != 1 {
		t.Fatalf("progress=%d failed=%+v", tk.Progress, tk.Failed)
	}
	if c := tk.Cursor(); c != 1 {
		t.Fatalf("cursor=%d want 1 (the failed entry)", c)
	}
	if tk.Done() {
		t.Fatal("task with failure must not be done")
	}

	// retry of the failed index resolves it
	must(tk.Record(1, "bcd.xyz", StatusAvailable, "", 6))
	if !tk.Done() || len(tk.Failed) != 0 || tk.Cursor() != 3 {
		t.Fatalf("after fix: done=%v cursor=%d failed=%+v", tk.Done(), tk.Cursor(), tk.Failed)
	}
}

func TestBeginSessionSkipsSettledIndices(t *testing.T) {
	tk := newTestTask(t)
	tk.Record(0, "a", StatusUnavailable, "", 1)
	tk.Record(1, "b", StatusFailed, "x", 3)
	tk.Record(2, "c", StatusAvailable, "", 1)

	if err := tk.SaveMeta(); err != nil {
		t.Fatal(err)
	}
	tk.CloseJournal()

	got, err := Load(tk.metaPath)
	if err != nil {
		t.Fatal(err)
	}
	defer got.CloseJournal()

	sess, err := got.BeginSession()
	if err != nil {
		t.Fatal(err)
	}
	if sess.Start != 1 {
		t.Fatalf("start=%d want 1", sess.Start)
	}
	// only index 2 (available) is settled; index 1 (failed) must be
	// re-checked, and index 3 is beyond Total=3.
	if !sess.ShouldSkip(2) || sess.ShouldSkip(1) || sess.ShouldSkip(3) {
		t.Fatalf("skip flags wrong: settled=%v", sess.Settled)
	}
	// simulate interrupt right after resuming; nothing lost or duplicated
	if err := got.SaveMeta(); err != nil {
		t.Fatal(err)
	}
	got.CloseJournal()
	re, err := Load(tk.metaPath)
	if err != nil {
		t.Fatal(err)
	}
	defer re.CloseJournal()
	// v3: Progress counts definitive outcomes only — the two available
	// records; the failed entry stays unsettled and retryable.
	if re.Progress != 2 || len(re.Failed) != 1 || re.Failed[0].Index != 1 {
		t.Fatalf("reload after session start: progress=%d failed=%+v", re.Progress, re.Failed)
	}
}

func TestCountsFromJournal(t *testing.T) {
	tk := newTestTask(t)
	tk.Record(0, "a", StatusAvailable, "", 1)
	tk.Record(1, "b", StatusUnavailable, "", 1)
	tk.Record(2, "c", StatusFailed, "down", 4)

	c, err := tk.Counts()
	if err != nil {
		t.Fatal(err)
	}
	if c.Available != 1 || c.Unavailable != 1 || c.Failed != 1 || c.Pending != 0 || c.Checked != 2 {
		t.Fatalf("counts=%+v", c)
	}

	// a retried-then-fixed index counts only by its latest line and leaves
	// the failed set
	tk.Record(2, "c", StatusAvailable, "", 6)
	c, err = tk.Counts()
	if err != nil {
		t.Fatal(err)
	}
	if c.Available != 2 || c.Unavailable != 1 || c.Failed != 0 || c.Checked != 3 || c.Pending != 0 {
		t.Fatalf("counts after fix=%+v", c)
	}
}

func TestExpiryStatusesAdvanceProgress(t *testing.T) {
	tk := newTestTask(t)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}

	must(tk.Record(0, "abc.xyz", StatusRedemption, "", 1))    // P=1
	must(tk.Record(1, "bcd.xyz", StatusPendingDelete, "", 1)) // P=2
	must(tk.Record(2, "cde.xyz", StatusUnavailable, "", 1))   // P=3

	if tk.Progress != 3 || tk.Cursor() != 3 || !tk.Done() {
		t.Fatalf("expiry-phase statuses are definitive: progress=%d cursor=%d done=%v",
			tk.Progress, tk.Cursor(), tk.Done())
	}
	c, err := tk.Counts()
	if err != nil {
		t.Fatal(err)
	}
	if c.Redemption != 1 || c.PendingDelete != 1 || c.Unavailable != 1 ||
		c.Checked != 3 || c.Pending != 0 {
		t.Fatalf("counts mismatch: %+v", c)
	}
}

func TestDNSStatusesAdvanceProgress(t *testing.T) {
	tk := newTestTask(t)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(tk.Record(0, "a", StatusUnavailableDNS, "", 1))
	must(tk.Record(1, "b", StatusAvailableDNS, "", 1))
	if tk.Progress != 2 || !tk.Done() == false {
		t.Fatalf("progress=%d", tk.Progress)
	}
	must(tk.Record(2, "c", StatusAvailableDNS, "", 1))
	if !tk.Done() || tk.Cursor() != 3 {
		t.Fatalf("done=%v cursor=%d", tk.Done(), tk.Cursor())
	}
	c, err := tk.Counts()
	if err != nil {
		t.Fatal(err)
	}
	if c.AvailableDNS != 2 || c.UnavailableDNS != 1 || c.Checked != 3 || c.Pending != 0 {
		t.Fatalf("counts=%+v", c)
	}

	// persisted across save/load
	if err := tk.SaveMeta(); err != nil {
		t.Fatal(err)
	}
	got, err := Load(tk.metaPath)
	if err != nil {
		t.Fatal(err)
	}
	defer got.CloseJournal()
	if !got.Done() || got.WhoisDisabled {
		t.Fatalf("reload: done=%v whoisDisabled=%v", got.Done(), got.WhoisDisabled)
	}
}

func TestWhoisDisabledRoundtrip(t *testing.T) {
	tk := newTestTask(t)
	tk.WhoisDisabled = true
	if err := tk.SaveMeta(); err != nil {
		t.Fatal(err)
	}
	got, err := Load(tk.metaPath)
	if err != nil {
		t.Fatal(err)
	}
	defer got.CloseJournal()
	if !got.WhoisDisabled {
		t.Fatal("whois_disabled must survive a roundtrip")
	}
}

func TestMetaStaysTinyWithFailures(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		TLD: "big", DictName: "huge",
		StatePath:   filepath.Join(dir, "t.state.json"),
		JournalPath: filepath.Join(dir, "t.journal"),
		Total:       1000000,
	}
	tk, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer tk.CloseJournal()

	const n = 50000
	for i := 0; i < n; i++ {
		st := StatusUnavailable
		errMsg := ""
		if i%1000 == 0 { // 50 permanent failures with long messages
			st = StatusFailed
			errMsg = strings.Repeat("dial tcp 10.255.255.1:43: connect: connection timed out; ", 8)
		}
		if err := tk.Record(i, "domain"+string(rune('a'+i%26))+".big", st, errMsg, 5); err != nil {
			t.Fatal(err)
		}
	}
	if err := tk.SaveMeta(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	// 50 failures × ~300B + base config — must be independent of the 50k records
	if fi.Size() > 32*1024 {
		t.Fatalf("meta file grew to %d bytes; must stay O(#failures)", fi.Size())
	}
	jfi, _ := os.Stat(cfg.JournalPath)
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	t.Logf("after %d records: meta=%dB journal=%dB heapInUse=%dKB",
		n, fi.Size(), jfi.Size(), ms.HeapInuse/1024)
}

func TestSaveLoadRoundtripV2(t *testing.T) {
	tk := newTestTask(t)
	tk.Record(0, "abc.xyz", StatusAvailable, "", 2)
	if err := tk.SaveMeta(); err != nil {
		t.Fatal(err)
	}
	got, err := Load(tk.metaPath)
	if err != nil {
		t.Fatal(err)
	}
	defer got.CloseJournal()
	if got.Version != currentVersion || got.Total != 3 || got.TLD != "xyz" ||
		got.NIC != "whois.nic.xyz" || got.Progress != 1 {
		t.Fatalf("roundtrip mismatch: version=%d total=%d tld=%s nic=%s progress=%d",
			got.Version, got.Total, got.TLD, got.NIC, got.Progress)
	}
	c, err := got.Counts()
	if err != nil {
		t.Fatal(err)
	}
	if c.Available != 1 {
		t.Fatalf("journal not preserved: %+v", c)
	}
}

// TestLoadDoesNotOpenJournal verifies the FD-leak fix: Load must NOT eagerly
// open the journal. Tasks loaded only for inspection (Resumable, the
// interactive resume menu) would otherwise leak a file handle each.
func TestLoadDoesNotOpenJournal(t *testing.T) {
	tk := newTestTask(t)
	if err := tk.Record(0, "abc.xyz", StatusAvailable, "", 2); err != nil {
		t.Fatal(err)
	}
	if err := tk.SaveMeta(); err != nil {
		t.Fatal(err)
	}
	tk.CloseJournal()

	got, err := Load(tk.metaPath)
	if err != nil {
		t.Fatal(err)
	}
	defer got.CloseJournal()
	if got.journalF != nil || got.journal != nil {
		t.Fatalf("Load must not open the journal eagerly (lazy on first write): journalF=%v journal=%v", got.journalF, got.journal)
	}
	// Reads must still work without an open journal handle.
	if _, err := got.Counts(); err != nil {
		t.Fatalf("Counts without open journal: %v", err)
	}
	if _, err := got.BeginSession(); err != nil {
		t.Fatalf("BeginSession without open journal: %v", err)
	}
	// The first write must lazily open the journal.
	if err := got.Record(1, "bcd.xyz", StatusUnavailable, "", 1); err != nil {
		t.Fatalf("first write after lazy Load: %v", err)
	}
	if got.journalF == nil || got.journal == nil {
		t.Fatalf("first write must lazily open the journal")
	}
}

// TestResumableDoesNotLeakJournalHandles ensures Resumable returns tasks
// whose journals are not open, so dropping the non-selected ones leaks
// nothing.
func TestResumableDoesNotLeakJournalHandles(t *testing.T) {
	dir := t.TempDir()
	open, err := New(Config{TLD: "a", DictName: "d",
		StatePath:   filepath.Join(dir, "open.state.json"),
		JournalPath: filepath.Join(dir, "open.journal"),
		Total:       2})
	if err != nil {
		t.Fatal(err)
	}
	if err := open.Record(0, "a0", StatusAvailable, "", 1); err != nil {
		t.Fatal(err)
	}
	if err := open.SaveMeta(); err != nil {
		t.Fatal(err)
	}
	open.CloseJournal()

	_, tasks, err := Resumable(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 1 {
		t.Fatalf("want 1 resumable task, got %d", len(tasks))
	}
	for i, tk := range tasks {
		if tk.journalF != nil || tk.journal != nil {
			t.Fatalf("task %d journal must be closed after Resumable: journalF=%v", i, tk.journalF)
		}
		tk.CloseJournal() // be tidy
	}
}

func TestLoadRejectsCorrupt(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.state.json")
	os.WriteFile(p, []byte("{not json"), 0o644)
	if _, err := Load(p); err == nil {
		t.Fatal("expected parse error")
	}
	os.WriteFile(p, []byte(`{"version":999}`), 0o644)
	if _, err := Load(p); err == nil {
		t.Fatal("expected version error")
	}
}

// TestUnorderedRecordingAndRebuild mirrors the two-queue scan: verdicts
// arrive in arbitrary order (DNS workers run ahead of the WHOIS consumer),
// the settled count must be order-independent, and a SaveMeta + Load
// roundtrip must rebuild the Settled bitmap exactly from the journal.
func TestUnorderedRecordingAndRebuild(t *testing.T) {
	tk := newTestTask(t)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}

	// Deliberately out of dictionary order.
	must(tk.Record(2, "c", StatusUnavailable, "", 1))
	must(tk.Record(0, "a", StatusAvailable, "", 1))
	must(tk.Record(1, "b", StatusFailed, "boom", 2)) // failed: unsettled

	if tk.Progress != 2 {
		t.Fatalf("settled count %d, want 2", tk.Progress)
	}
	if c := tk.Cursor(); c != 1 {
		t.Fatalf("cursor=%d want 1 (failed index)", c)
	}

	if err := tk.SaveMeta(); err != nil {
		t.Fatal(err)
	}
	tk.CloseJournal()
	got, err := Load(tk.metaPath)
	if err != nil {
		t.Fatal(err)
	}
	defer got.CloseJournal()
	want := []byte{1, 0, 1}
	for i := range want {
		if got.Settled[i] != want[i] {
			t.Fatalf("rebuilt settled=%v, want %v", got.Settled, want)
		}
	}
	if got.Progress != 2 {
		t.Fatalf("rebuilt progress=%d, want 2", got.Progress)
	}

	// duplicate settled re-record is rejected even unordered
	if err := got.Record(2, "c", StatusAvailable, "", 1); err == nil {
		t.Fatal("duplicate settled record must be rejected")
	}
	// and the failed index can still be retried to completion
	must(got.Record(1, "b", StatusAvailable, "", 3))
	if !got.Done() {
		t.Fatal("task should be done after retry settles the failure")
	}
}

func TestRecordValidation(t *testing.T) {
	tk := newTestTask(t)
	if err := tk.Record(99, "x", StatusAvailable, "", 1); err == nil {
		t.Fatal("expected out-of-range error")
	}
	if err := tk.Record(0, "x", StatusPending, "", 1); err == nil {
		t.Fatal("expected invalid-status error")
	}
	// v3: records may arrive out of order (DNS workers run ahead of the
	// WHOIS consumer); an unordered failure is now accepted.
	if err := tk.Record(1, "b", StatusFailed, "e", 1); err != nil {
		t.Fatalf("unordered failed record should be accepted: %v", err)
	}
	// re-recording a settled index is still an ordering bug
	if err := tk.Record(0, "a", StatusAvailable, "", 1); err != nil {
		t.Fatal(err)
	}
	if err := tk.Record(0, "a", StatusAvailable, "", 2); err == nil {
		t.Fatal("duplicate conclusive record should be rejected")
	}
	if err := tk.Record(0, "a", StatusFailed, "e", 1); err == nil {
		t.Fatal("failing a settled record should be rejected")
	}

	// normal flow: fail first (stays unsettled), retry-fix settles it.
	if err := tk.Record(2, "c", StatusFailed, "e2", 2); err != nil {
		t.Fatalf("upserting an existing failure should be accepted: %v", err)
	}
	if err := tk.Record(2, "c", StatusAvailable, "", 3); err != nil {
		t.Fatalf("retry-fix should be accepted: %v", err)
	}
	if err := tk.Record(2, "c", StatusAvailable, "", 4); err == nil {
		t.Fatal("duplicate conclusive record should be rejected")
	}
}

func TestMigrateV1(t *testing.T) {
	dir := t.TempDir()
	v1 := `{
	  "version": 1,
	  "tld": "xyz", "dict": "test", "nic": "whois.nic.xyz",
	  "response_marker": "object does not exist", "delay_seconds": 0,
	  "log_path": "` + filepath.ToSlash(filepath.Join(dir, "old.log")) + `",
	  "prefixes": ["abc", "bcd", "cde"],
	  "results": [
	    {"domain":"abc.xyz","status":"unavailable","attempts":1},
	    {"domain":"bcd.xyz","status":"failed","error":"net down","attempts":5},
	    {"domain":"cde.xyz","status":"pending"}
	  ],
	  "cursor": 1
	}`
	p := filepath.Join(dir, "old_xyz_test_1.state.json")
	if err := os.WriteFile(p, []byte(v1), 0o644); err != nil {
		t.Fatal(err)
	}

	tk, err := Load(p)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	defer tk.CloseJournal()
	if tk.Version != currentVersion || tk.Total != 3 || tk.Progress != 1 || len(tk.Failed) != 1 {
		t.Fatalf("migrated task wrong: progress=%d failed=%+v", tk.Progress, tk.Failed)
	}
	if tk.Cursor() != 1 {
		t.Fatalf("cursor=%d want 1", tk.Cursor())
	}
	// journal was synthesized from v1 results (failed + unavailable lines)
	data, _ := os.ReadFile(filepath.Join(dir, "old_xyz_test_1.journal"))
	if lines := strings.Count(strings.TrimSpace(string(data)), "\n") + 1; lines != 2 {
		t.Fatalf("journal should hold 2 migrated results, has %d: %q", lines, data)
	}
	// resumable picks it up
	paths, tasks, err := Resumable(dir)
	if err != nil || len(tasks) != 1 {
		t.Fatalf("resumable: %v %d", err, len(tasks))
	}
	if paths[0] != p {
		t.Fatalf("path changed: %s", paths[0])
	}
}

func TestResumableFindsIncompleteNewestFirst(t *testing.T) {
	dir := t.TempDir()

	doneTask, err := New(Config{TLD: "a", DictName: "d", StatePath: filepath.Join(dir, "done.state.json"), JournalPath: filepath.Join(dir, "done.journal"), Total: 1})
	if err != nil {
		t.Fatal(err)
	}
	doneTask.Record(0, "x.a", StatusUnavailable, "", 1)
	doneTask.SaveMeta()
	doneTask.CloseJournal()
	time.Sleep(10 * time.Millisecond)

	openTask, err := New(Config{TLD: "b", DictName: "d", StatePath: filepath.Join(dir, "open.state.json"), JournalPath: filepath.Join(dir, "open.journal"), Total: 2})
	if err != nil {
		t.Fatal(err)
	}
	openTask.Record(0, "x.b", StatusFailed, "net down", 3)
	openTask.SaveMeta()
	openTask.CloseJournal()

	os.WriteFile(filepath.Join(dir, "corrupt.state.json"), []byte("garbage"), 0o644)

	paths, tasks, err := Resumable(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 1 {
		t.Fatalf("expected exactly 1 resumable task, got %d (%v)", len(tasks), paths)
	}
	if tasks[0].TLD != "b" || tasks[0].Failed[0].Error != "net down" {
		t.Fatalf("wrong task: %+v", tasks[0])
	}
}
