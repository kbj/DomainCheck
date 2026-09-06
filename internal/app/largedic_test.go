package app

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/uselibrary/DomainCheck/internal/dns/dnstest"
	"github.com/uselibrary/DomainCheck/internal/state"
)

// TestLargeDictStreamedScanResume exercises the streaming dictionary path
// end to end with 10k entries: interrupt mid-scan, then resume and verify
// the journal index alignment (journal idx must map back to the right
// dictionary entry) and the "settled domains are skipped" invariant.
//
// 10k is deliberately modest for CI speed; the point is exercising the
// streaming path, not memory measurement.
func TestLargeDictStreamedScanResume(t *testing.T) {
	dir := setupDataDir(t)

	// Build a 10_000-entry dictionary with unique prefixes e00000..e09999,
	// with blank lines sprinkled in to verify that streamed indices match
	// the Load semantics (blank lines are not entries).
	const total = 10_000
	var sb strings.Builder
	for i := 0; i < total; i++ {
		sb.WriteString(fmt.Sprintf("e%05d\n", i))
		if i%97 == 0 { // noise lines that must not shift indices
			sb.WriteString("\n")
		}
	}
	dictPath := filepath.Join(dir, "dict", "big")
	if err := os.WriteFile(dictPath, []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	opts, fw, _ := newTestOptionsWithDNS(t, dir,
		func(d string) string { return d + ": object does not exist\n" },
		func(string) dnstest.Response { return dnstest.Response{RCode: 3} })
	opts.DictName = "big"

	// Cancel as soon as the third WHOIS query overall lands (~Ctrl+C
	// mid-scan). Counting globally (not per-domain) makes the trigger
	// independent of which domain is in flight.
	var mu sync.Mutex
	var queries int
	var cancelled bool
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fw.setBehavior(func(d string) string {
		mu.Lock()
		queries++
		n := queries
		mu.Unlock()
		if !cancelled && n >= 3 {
			cancelled = true
			cancel()
		}
		return d + ": object does not exist\n"
	})

	err := Run(ctx, opts)
	if err == nil || !strings.Contains(err.Error(), "interrupted") {
		t.Fatalf("want interrupted run, got %v", err)
	}

	statePath := soleStatePath(t, dir)
	tk, err := state.Load(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer tk.CloseJournal()
	if tk.Total != total {
		t.Fatalf("recorded total=%d, want %d", tk.Total, total)
	}
	checked1 := tk.Progress
	if checked1 < 1 || checked1 > total {
		t.Fatalf("progress after interrupt out of range: %d", checked1)
	}

	// Resume: everything finishes, and the journal index ↔ entry mapping
	// stays exact — settled entries from session 1 are never re-queried,
	// and spot-checked entries get at most 2 hits (a second hit is only
	// legitimate for the domain that was in flight when the interrupt
	// landed; it had no verdict yet, so the resume re-queries it).
	resumeOpts := opts
	resumeOpts.Resume = statePath
	resumeOpts.Stdout = &bytes.Buffer{}
	if err := Run(context.Background(), resumeOpts); err != nil {
		t.Fatalf("resume: %v", err)
	}

	for _, i := range []int{0, 1, checked1 - 1, checked1, total - 1} {
		d := fmt.Sprintf("e%05d.xyz", i)
		n := fw.hitCount(d)
		if n < 1 {
			t.Fatalf("index %d (%s) never queried", i, d)
		}
		if i < checked1-1 && n > 1 {
			t.Fatalf("index %d (%s) queried %d times: settled entries must be skipped", i, d, n)
		}
		if n > 2 {
			t.Fatalf("index %d (%s) queried %d times: even an in-flight re-check allows only 2", i, d, n)
		}
	}
	out := resumeOpts.Stdout.(*bytes.Buffer).String()
	if !strings.Contains(out, fmt.Sprintf("Task Done: %d domains", total)) {
		t.Fatalf("summary mismatch:\n%s", out)
	}
}
