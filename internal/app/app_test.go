package app

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uselibrary/DomainCheck/internal/dns"
	"github.com/uselibrary/DomainCheck/internal/dns/dnstest"
	"github.com/uselibrary/DomainCheck/internal/state"
	"github.com/uselibrary/DomainCheck/internal/whois"
)

// fakeWhois is a scriptable WHOIS server for end-to-end tests.
type fakeWhois struct {
	t        *testing.T
	listener net.Listener
	port     int

	mu    sync.Mutex
	hits  map[string]int
	order []string

	// behave decides the raw response for a domain. Returning "" closes the
	// connection without sending anything (simulates a network failure).
	behave func(domain string) string
}

func newFakeWhois(t *testing.T, behave func(domain string) string) *fakeWhois {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	fw := &fakeWhois{t: t, listener: ln, port: ln.Addr().(*net.TCPAddr).Port, hits: map[string]int{}, behave: behave}
	go fw.serve()
	t.Cleanup(func() { ln.Close() })
	return fw
}

func (fw *fakeWhois) serve() {
	for {
		conn, err := fw.listener.Accept()
		if err != nil {
			return
		}
		go fw.handle(conn)
	}
}

func (fw *fakeWhois) handle(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return
	}
	domain := strings.TrimSpace(line)
	fw.mu.Lock()
	fw.hits[domain]++
	fw.order = append(fw.order, domain)
	behave := fw.behave
	fw.mu.Unlock()
	var out string
	if behave != nil {
		out = behave(domain)
	}
	if out != "" {
		conn.Write([]byte(out))
	}
}

func (fw *fakeWhois) hitCount(domain string) int {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	return fw.hits[domain]
}

// setBehavior swaps the response script at any time.
func (fw *fakeWhois) setBehavior(fn func(domain string) string) {
	fw.mu.Lock()
	fw.behave = fn
	fw.mu.Unlock()
}

// setupDataDir creates tld.json + dict/test inside a temp dir.
func setupDataDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "dict"), 0o755)
	reg := `{"xyz": {"nic": "127.0.0.1", "response": "object does not exist"}}`
	if err := os.WriteFile(filepath.Join(dir, "tld.json"), []byte(reg), 0o644); err != nil {
		t.Fatal(err)
	}
	dictContent := "abc\nbcd\ncde\n"
	if err := os.WriteFile(filepath.Join(dir, "dict", "test"), []byte(dictContent), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// testOptions builds run options around a fresh fake whois server plus a
// fake DNS server. The default DNS answer is NXDOMAIN (no NS records), so
// every domain falls through to the WHOIS path unless a test overrides it.
func testOptions(t *testing.T, dir string, behave func(string) string) (Options, *fakeWhois) {
	fw := newFakeWhois(t, behave)
	dnsSrv := dnstest.Start(t)
	dnsSrv.SetBehavior(func(d string) dnstest.Response { return dnstest.Response{RCode: 3} })
	opts := Options{
		DataDir:   dir,
		TLD:       "xyz",
		DictName:  "test",
		DelaySecs: 0,
		DNS: dns.Options{
			Server:     dnsSrv.Addr(),
			Timeout:    300 * time.Millisecond,
			MaxRetries: 2,
			BaseDelay:  5 * time.Millisecond,
			MaxDelay:   15 * time.Millisecond,
		},
		Whois: whois.Options{
			Port:       fw.port,
			Timeout:    300 * time.Millisecond,
			MaxRetries: 2,
			BaseDelay:  5 * time.Millisecond,
			MaxDelay:   15 * time.Millisecond,
		},
		Stdout: &bytes.Buffer{},
		Stderr: &bytes.Buffer{},
	}
	return opts, fw
}

// testDNS exposes the fake DNS server of an options set for behavior tweaks.
var lastDNSServer *dnstest.Server

func newTestOptionsWithDNS(t *testing.T, dir string, behave func(string) string,
	dnsBehave func(string) dnstest.Response) (Options, *fakeWhois, *dnstest.Server) {
	fw := newFakeWhois(t, behave)
	dnsSrv := dnstest.Start(t)
	dnsSrv.SetBehavior(dnsBehave)
	opts := Options{
		DataDir:   dir,
		TLD:       "xyz",
		DictName:  "test",
		DelaySecs: 0,
		DNS: dns.Options{
			Server:     dnsSrv.Addr(),
			Timeout:    300 * time.Millisecond,
			MaxRetries: 2,
			BaseDelay:  5 * time.Millisecond,
			MaxDelay:   15 * time.Millisecond,
		},
		Whois: whois.Options{
			Port:       fw.port,
			Timeout:    300 * time.Millisecond,
			MaxRetries: 2,
			BaseDelay:  5 * time.Millisecond,
			MaxDelay:   15 * time.Millisecond,
		},
		Stdout: &bytes.Buffer{},
		Stderr: &bytes.Buffer{},
	}
	return opts, fw, dnsSrv
}

func soleStatePath(t *testing.T, dir string) string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "state", "*.state.json"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("expected exactly one state file in %s/state, got %v (err=%v)", dir, matches, err)
	}
	return matches[0]
}

func TestEndToEndFullRun(t *testing.T) {
	dir := setupDataDir(t)
	available := map[string]bool{"abc.xyz": true, "cde.xyz": true}
	opts, _ := testOptions(t, dir, func(d string) string {
		if available[d] {
			return d + "\nobject does not exist\n"
		}
		return d + "\nRegistrar: someone\n"
	})

	if err := Run(context.Background(), opts); err != nil {
		t.Fatalf("run: %v", err)
	}

	out := opts.Stdout.(*bytes.Buffer).String()
	for _, want := range []string{"Task Start", "abc.xyz is available", "bcd.xyz is NOT available", "cde.xyz is available"} {
		if !strings.Contains(out, want) {
			t.Fatalf("stdout missing %q; got:\n%s", want, out)
		}
	}

	// A finished task must be neither resumable nor leave checkpoints behind.
	_, tasks, err := state.Resumable(dir + "/state")
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 0 {
		t.Fatalf("finished task must not be resumable, got %d", len(tasks))
	}
	leftover, _ := filepath.Glob(filepath.Join(dir, "state", "*"))
	if len(leftover) != 0 {
		t.Fatalf("completed task must delete its checkpoints, left: %v", leftover)
	}
	if !strings.Contains(out, "Task Done: 3 domains — 2 available (0 uncertain-dns), 1 NOT available (0 via-dns), 0 failed") {
		t.Fatalf("summary mismatch:\n%s", out)
	}

	// The result log stays and follows the original Python format.
	logMatches, err := filepath.Glob(filepath.Join(dir, "result", "*.log"))
	if err != nil || len(logMatches) != 1 {
		t.Fatalf("expected exactly one log in %s/result, got %v (err=%v)", dir, logMatches, err)
	}
	logBytes, err := os.ReadFile(logMatches[0])
	if err != nil {
		t.Fatal(err)
	}
	log := string(logBytes)
	if !strings.HasPrefix(log, "TLD: xyz Dict: test Delay: 0 Time: ") {
		t.Fatalf("log header wrong:\n%s", log)
	}
	if !strings.Contains(log, "abc.xyz is available\n") || !strings.Contains(log, "cde.xyz is available\n") {
		t.Fatalf("log missing available entries:\n%s", log)
	}
	if strings.Contains(log, "NOT available") {
		t.Fatalf("original log format records only available domains:\n%s", log)
	}
	if !strings.Contains(log, " Task Done") {
		t.Fatalf("log missing footer:\n%s", log)
	}
}

func TestErrorDoesNotAbortRunAndStateIsRemembered(t *testing.T) {
	dir := setupDataDir(t)
	opts, fw, _ := newTestOptionsWithDNS(t, dir,
		func(d string) string {
			if d == "bcd.xyz" {
				return "" // whois server rejects this domain outright
			}
			return d + ": no match\n"
		},
		func(d string) dnstest.Response { return dnstest.Response{RCode: 3} }, // no NS anywhere
	)

	if err := Run(context.Background(), opts); err != nil {
		t.Fatalf("a failing domain must NOT abort the run, got: %v", err)
	}

	out := opts.Stdout.(*bytes.Buffer).String()
	for _, want := range []string{
		"Falling back to DNS-NS-only mode",
		"bcd.xyz is available [dns, uncertain]",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("stdout missing %q:\n%s", want, out)
		}
	}

	leftover, _ := filepath.Glob(filepath.Join(dir, "state", "*"))
	if len(leftover) != 0 {
		t.Fatalf("fully judged task must delete its checkpoints, left: %v", leftover)
	}
	if !strings.Contains(out, "Task Done: 3 domains") || !strings.Contains(out, "(2 uncertain-dns)") {
		t.Fatalf("summary should reflect dns verdicts:\n%s", out)
	}
	_ = fw
}
func statePath0(opts Options) string {
	matches, _ := filepath.Glob(opts.DataDir + "/result/*.state.json")
	if len(matches) == 0 {
		return "<none>"
	}
	return matches[0]
}

func TestResumeKeepsDegradationAndRetriesUnfinished(t *testing.T) {
	dir := setupDataDir(t)

	// bcd: whois rejects it AND dns lookups fail -> recorded as failed.
	// Everything else resolves normally through whois (dns says NXDOMAIN).
	var whoisFailMode, dnsFailMode atomic.Bool
	opts, fw, _ := newTestOptionsWithDNS(t, dir,
		func(d string) string {
			if whoisFailMode.Load() && d == "bcd.xyz" {
				return ""
			}
			return d + ": no match\n"
		},
		func(d string) dnstest.Response {
			// Match search-domain variants too ("bcd.xyz.<search>"), or the
			// resolver would treat their NXDOMAIN as authoritative.
			if dnsFailMode.Load() && strings.Contains(d, "bcd") {
				return dnstest.Response{RCode: 2} // SERVFAIL every attempt
			}
			return dnstest.Response{RCode: 3} // NXDOMAIN: no NS records
		})
	whoisFailMode.Store(true)
	dnsFailMode.Store(true)

	if err := Run(context.Background(), opts); err != nil {
		t.Fatalf("first run: %v", err)
	}
	errOut := opts.Stderr.(*bytes.Buffer).String()
	if !strings.Contains(errOut, "WARN bcd.xyz failed permanently") {
		meta, _ := os.ReadFile(statePath0(opts))
		t.Fatalf("bcd should end up failed (dns+whois both down):\nstderr:\n%s\nmeta:\n%s", errOut, meta)
	}

	statePath := soleStatePath(t, dir)
	tk, err := state.Load(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer tk.CloseJournal()
	if len(tk.Failed) != 1 || tk.Failed[0].Index != 1 || tk.Done() {
		cdbg, _ := tk.Counts()
		t.Fatalf("bcd must be the sole failed entry: failed=%+v progress=%d counts=%+v whoisDisabled=%v",
			tk.Failed, tk.Progress, cdbg, tk.WhoisDisabled)
	}
	bcdWhoisHits := fw.hitCount("bcd.xyz")

	// Second run: everything healthy again, resume from saved state.
	// Degradation must persist (no whois traffic), but bcd gets re-judged
	// via DNS while settled domains are skipped entirely.
	whoisFailMode.Store(false)
	dnsFailMode.Store(false)
	resumeOpts := opts
	resumeOpts.Stdout = &bytes.Buffer{}
	resumeOpts.Resume = statePath
	if err := Run(context.Background(), resumeOpts); err != nil {
		t.Fatalf("resume run: %v", err)
	}

	if got := fw.hitCount("bcd.xyz"); got != bcdWhoisHits {
		t.Fatalf("degraded task must not touch whois again: %d -> %d", bcdWhoisHits, got)
	}
	if got := fw.hitCount("abc.xyz"); got != 1 {
		t.Fatalf("settled domains must be skipped on resume, abc hits=%d", got)
	}

	leftover, _ := filepath.Glob(filepath.Join(dir, "state", "*"))
	if len(leftover) != 0 {
		t.Fatalf("fully resumed task must delete its checkpoints, left: %v", leftover)
	}
	out := resumeOpts.Stdout.(*bytes.Buffer).String()
	if !strings.Contains(out, "Resuming xyz_test") || !strings.Contains(out, "[dns") ||
		!strings.Contains(out, "Task Done: 3 domains") {
		t.Fatalf("resume banner/dns tags/summary missing:\n%s", out)
	}
}

func TestInterruptSavesProgressAndResumes(t *testing.T) {
	dir := setupDataDir(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Cancel the context as soon as the SECOND domain arrives (Ctrl+C-like).
	opts, _ := testOptions(t, dir, func(d string) string {
		if d == "bcd.xyz" {
			cancel() // simulate Ctrl+C right when bcd is being queried
			time.Sleep(10 * time.Millisecond)
		}
		return d + ": no match\n"
	})

	err := Run(ctx, opts)
	if err == nil || !strings.Contains(err.Error(), "interrupted") {
		t.Fatalf("want ErrInterrupted, got %v", err)
	}

	statePath := soleStatePath(t, dir) // progress must already be on disk
	tk, err := state.Load(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer tk.CloseJournal()
	c, err := tk.Counts()
	if err != nil {
		t.Fatal(err)
	}
	if c.Checked < 1 {
		t.Fatalf("first result must be persisted before interruption: %+v", c)
	}
	if tk.Done() || tk.Cursor() >= 3 {
		t.Fatalf("task must be incomplete after interrupt: cursor=%d counts=%+v", tk.Cursor(), c)
	}
	out := opts.Stdout.(*bytes.Buffer).String()
	if !strings.Contains(out, "****Task Interrupted (progress saved)****") {
		t.Fatalf("interrupt notice missing:\n%s", out)
	}

	// Resume without cancelling: finishes everything.
	resumeOpts := opts
	resumeOpts.Resume = statePath
	resumeOpts.Stdout = &bytes.Buffer{}
	if err := Run(context.Background(), resumeOpts); err != nil {
		t.Fatalf("resume: %v", err)
	}
	out2 := resumeOpts.Stdout.(*bytes.Buffer).String()
	if !strings.Contains(out2, "Task Done: 3 domains") {
		t.Fatalf("resumed task should finish:\n%s", out2)
	}
	leftover, _ := filepath.Glob(filepath.Join(dir, "state", "*"))
	if len(leftover) != 0 {
		t.Fatalf("completed task must delete its checkpoints, left: %v", leftover)
	}
}

func TestInteractiveFlow(t *testing.T) {
	dir := setupDataDir(t)
	opts, _ := testOptions(t, dir, func(d string) string {
		return d + ": object does not exist\n"
	})
	opts.Interactive = true
	opts.TLD, opts.DictName = "", ""
	opts.Stdin = strings.NewReader("xyz\ntest\n0\n")

	if err := Run(context.Background(), opts); err != nil {
		t.Fatalf("interactive run: %v", err)
	}
	out := opts.Stdout.(*bytes.Buffer).String()
	for _, want := range []string{"Enter tld name:", "Enter dict name:", "Enter delay [0]:", "Task Start", "Task Done"} {
		if !strings.Contains(out, want) {
			t.Fatalf("interactive output missing %q:\n%s", want, out)
		}
	}

	// Invalid TLD first, then valid: prompt must re-ask instead of dying.
	opts2, _ := testOptions(t, dir, func(d string) string { return d + ": x\n" })
	opts2.Interactive = true
	opts2.Stdin = strings.NewReader("nope\nn\nxyz\ntest\n0\n")
	if err := Run(context.Background(), opts2); err != nil {
		t.Fatalf("interactive run with retry input: %v", err)
	}
	out2 := opts2.Stdout.(*bytes.Buffer).String()
	if !strings.Contains(out2, "not configured in tld.json") || !strings.Contains(out2, "[y/N]:") {
		t.Fatalf("unknown tld should offer DNS-only confirmation:\n%s", out2)
	}
}

func TestJitteredDelayStaysAroundBase(t *testing.T) {
	// zero/negative base must not sleep at all
	if d := jitteredDelay(0); d != 0 {
		t.Fatalf("jitteredDelay(0) = %v, want 0", d)
	}
	if d := jitteredDelay(-time.Second); d != 0 {
		t.Fatalf("negative base = %v, want 0", d)
	}

	bases := []time.Duration{
		time.Millisecond, 10 * time.Millisecond, time.Second,
		5 * time.Second, time.Minute,
	}
	for _, base := range bases {
		spread := base / 4
		low, high := base-spread, base+spread
		for i := 0; i < 500; i++ {
			d := jitteredDelay(base)
			if d < low || d > high {
				t.Fatalf("base=%v: delay %v outside [%v, %v]", base, d, low, high)
			}
		}
	}

	// sanity: values should actually vary (not a constant in disguise)
	base := time.Second
	seen := map[time.Duration]bool{}
	for i := 0; i < 100; i++ {
		seen[jitteredDelay(base)] = true
	}
	if len(seen) < 10 {
		t.Fatalf("expected varied delays, got only %d distinct values", len(seen))
	}
}

func TestDNSPreCheckSkipsWhois(t *testing.T) {
	dir := setupDataDir(t)
	// abc and cde have NS records -> registered via DNS, whois never asked.
	opts, fw, _ := newTestOptionsWithDNS(t, dir,
		func(d string) string { return d + ": object does not exist\n" },
		func(d string) dnstest.Response {
			if d == "abc.xyz" || d == "cde.xyz" {
				return dnstest.Response{NSNames: []string{"ns1." + d}}
			}
			return dnstest.Response{RCode: 3}
		})

	if err := Run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}

	for _, d := range []string{"abc.xyz", "cde.xyz"} {
		if fw.hitCount(d) != 0 {
			t.Fatalf("%s has NS records; whois must be skipped, hits=%d", d, fw.hitCount(d))
		}
		if fw.hitCount("bcd.xyz") == 0 {
			t.Fatalf("bcd.xyz (no NS) must still be whois-checked")
		}
	}

	out := opts.Stdout.(*bytes.Buffer).String()
	if !strings.Contains(out, "abc.xyz is NOT available [dns]") ||
		!strings.Contains(out, "cde.xyz is NOT available [dns]") {
		t.Fatalf("dns-derived results must be tagged:\n%s", out)
	}

	if !strings.Contains(out, "Task Done: 3 domains") || !strings.Contains(out, "(2 via-dns)") {
		t.Fatalf("summary should count dns results:\n%s", out)
	}
	leftover, _ := filepath.Glob(filepath.Join(dir, "state", "*"))
	if len(leftover) != 0 {
		t.Fatalf("completed task must delete its checkpoints, left: %v", leftover)
	}
}

func TestUnconfiguredTLDRunsDNSOnly(t *testing.T) {
	dir := setupDataDir(t)
	// tld.json only knows "xyz"; scan an unconfigured TLD in flag mode.
	opts, _, _ := newTestOptionsWithDNS(t, dir,
		func(d string) string { t.Fatalf("whois must never be contacted for %s", d); return "" },
		func(d string) dnstest.Response {
			if strings.HasPrefix(d, "bcd") {
				return dnstest.Response{NSNames: []string{"ns1." + d}} // registered
			}
			return dnstest.Response{RCode: 3} // no NS: probably available
		})
	opts.TLD = "qqq" // not in tld.json
	opts.DictName = "test"

	if err := Run(context.Background(), opts); err != nil {
		t.Fatalf("unconfigured TLD should run in dns-only mode, got: %v", err)
	}

	out := opts.Stdout.(*bytes.Buffer).String()
	for _, want := range []string{
		"NOT configured in tld.json",
		"NOT fully reliable",
		"bcd.qqq is NOT available [dns]",
		"abc.qqq is available [dns, uncertain]",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}

	if !strings.Contains(out, "Task Done: 3 domains") || !strings.Contains(out, "(1 via-dns)") {
		t.Fatalf("dns-only summary expected:\n%s", out)
	}
}

func TestInteractiveUnconfiguredTLDConfirm(t *testing.T) {
	dir := setupDataDir(t)
	opts, _, _ := newTestOptionsWithDNS(t, dir,
		func(d string) string { return d + ": x\n" },
		func(d string) dnstest.Response {
			if strings.HasPrefix(d, "bcd") {
				return dnstest.Response{NSNames: []string{"ns1." + d}}
			}
			return dnstest.Response{RCode: 3}
		})
	opts.Interactive = true
	opts.TLD, opts.DictName = "", ""
	// user picks unconfigured tld "qqq", confirms with "y"
	opts.Stdin = strings.NewReader("qqq\ny\ntest\n0\n")

	if err := Run(context.Background(), opts); err != nil {
		t.Fatalf("interactive dns-only run: %v", err)
	}
	out := opts.Stdout.(*bytes.Buffer).String()
	if !strings.Contains(out, "NOT fully reliable") || !strings.Contains(out, "bcd.qqq is NOT available [dns]") {
		t.Fatalf("expected confirmation flow and dns-only results:\n%s", out)
	}
}

func TestGenerateDict(t *testing.T) {
	dir := t.TempDir() // no dict/ subdir yet: generator must create it
	opts := Options{DataDir: dir, Gen: true, Charset: "ab1", WordLen: 3, OutName: "gen.txt"}
	var out bytes.Buffer
	opts.Stdout = &out

	if err := generateDict(opts, func(f string, a ...any) { fmt.Fprintf(&out, f+"\n", a...) },
		func(string, ...any) {}); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "dict", "gen.txt"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	want := []string{"aaa", "aab", "aa1", "aba", "abb", "ab1", "a1a", "a1b", "a11",
		"baa", "bab", "ba1", "bba", "bbb", "bb1", "b1a", "b1b", "b11",
		"1aa", "1ab", "1a1", "1ba", "1bb", "1b1", "11a", "11b", "111"}
	if len(lines) != len(want) {
		t.Fatalf("got %d lines, want %d", len(lines), len(want))
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Fatalf("line %d: got %q want %q", i, lines[i], want[i])
		}
	}
	if !strings.Contains(out.String(), "Entries: 27") {
		t.Fatalf("summary missing:\n%s", out.String())
	}

	// refuse to clobber an existing dictionary
	err = generateDict(opts, func(string, ...any) {}, func(string, ...any) {})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("overwrite must be rejected, got %v", err)
	}

	// duplicate characters in the charset are collapsed
	dup := opts
	dup.Charset, dup.WordLen, dup.OutName = "aab", 2, "dup.txt"
	if err := generateDict(dup, func(string, ...any) {}, func(string, ...any) {}); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(filepath.Join(dir, "dict", "dup.txt"))
	if n := strings.Count(string(data), "\n"); n != 4 { // aa ab ba bb
		t.Fatalf("deduped charset should yield 4 entries, got %d", n)
	}

	// multibyte runes work too
	uni := Options{DataDir: dir, Gen: true, Charset: "中文", WordLen: 2, OutName: "uni.txt"}
	if err := generateDict(uni, func(string, ...any) {}, func(string, ...any) {}); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(filepath.Join(dir, "dict", "uni.txt"))
	if !strings.Contains(string(data), "中文\n") || !strings.Contains(string(data), "文中") {
		t.Fatalf("unicode combos wrong:\n%s", data)
	}

	// validation errors
	cases := []Options{
		{DataDir: dir, Gen: true, Charset: "", WordLen: 2, OutName: "x"},
		{DataDir: dir, Gen: true, Charset: "ab", WordLen: 0, OutName: "x"},
		{DataDir: dir, Gen: true, Charset: "ab", WordLen: 2, OutName: ""},
		{DataDir: dir, Gen: true, Charset: "ab", WordLen: 2, OutName: "../escape"},
		{DataDir: dir, Gen: true, Charset: "abcdefghijklmnopqrstuvwxyz0123456789", WordLen: 20, OutName: "huge"},
	}
	for i, c := range cases {
		if err := generateDict(c, func(string, ...any) {}, func(string, ...any) {}); err == nil {
			t.Fatalf("case %d should fail", i)
		}
	}
}

func TestResultAndStateDirsAutoCreated(t *testing.T) {
	dir := setupDataDir(t)
	os.RemoveAll(filepath.Join(dir, "result")) // simulate fresh checkout
	opts, _ := testOptions(t, dir, func(d string) string { return d + ": object does not exist\n" })
	if err := Run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"result", "state"} {
		if fi, err := os.Stat(filepath.Join(dir, sub)); err != nil || !fi.IsDir() {
			t.Fatalf("%s/ must be auto-created", sub)
		}
	}
	// completed scan: state/ holds nothing anymore, result/ keeps the log
	if ents, _ := os.ReadDir(filepath.Join(dir, "state")); len(ents) != 0 {
		t.Fatalf("state/ should be empty after completion")
	}
	if logs, _ := os.ReadDir(filepath.Join(dir, "result")); len(logs) != 1 {
		t.Fatalf("result/ should keep the log")
	}
}

func TestInterQueryDelay(t *testing.T) {
	// Pure-DNS verdicts: exactly the configured interval, never jittered.
	for _, iv := range []time.Duration{100 * time.Millisecond, time.Second, 3 * time.Second} {
		for i := 0; i < 20; i++ {
			if d := interQueryDelay(false, 10, iv); d != iv {
				t.Fatalf("dns path must equal -dns-interval verbatim: want %v got %v", iv, d)
			}
		}
	}
	// Whois path with delay=0: no wait (original tool behavior preserved).
	if d := interQueryDelay(true, 0, time.Second); d != 0 {
		t.Fatalf("whois path delay=0 should be 0, got %v", d)
	}
	// Whois path with configured delay: jittered around it; dns interval
	// value must not leak into the whois path.
	low, high := 3*time.Second, 5*time.Second
	sawVariation := false
	var last time.Duration
	for i := 0; i < 200; i++ {
		d := interQueryDelay(true, 4, time.Second)
		if d < low || d > high {
			t.Fatalf("whois delay %v outside [%v,%v]", d, low, high)
		}
		if last != 0 && d != last {
			sawVariation = true
		}
		last = d
	}
	if !sawVariation {
		t.Fatal("whois delay should vary (jitter)")
	}
}
