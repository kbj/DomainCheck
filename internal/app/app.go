// Package app wires everything together: user input, the scan loop,
// result logging and crash-safe state handling.
package app

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/uselibrary/DomainCheck/internal/config"
	"github.com/uselibrary/DomainCheck/internal/dict"
	"github.com/uselibrary/DomainCheck/internal/dns"
	"github.com/uselibrary/DomainCheck/internal/state"
	"github.com/uselibrary/DomainCheck/internal/whois"
)

// ErrInterrupted is returned when the run stopped because the context was
// cancelled (Ctrl+C / SIGTERM). Progress has been saved when this is returned.
var ErrInterrupted = errors.New("interrupted")

// Options controls one invocation.
type Options struct {
	// DataDir holds tld.json, dict/ and result/. Defaults to ".".
	DataDir string
	// TLD, DictName, DelaySecs describe a NEW task (non-interactive mode
	// when set; prompts are skipped).
	TLD       string
	DictName  string
	DelaySecs int
	// Resume selects a saved task to continue: "" starts new, "latest" (or
	// "true") resumes the most recently updated unfinished task, any other
	// value is treated as a path to a specific *.state.json file.
	Resume string
	// Interactive enables the original prompt-driven flow (used when no
	// task flags were given on the command line).
	Interactive bool

	ListTLDs  bool
	ListDicts bool

	// DNS configures the NS pre-check lookups (resolver override, retries,
	// backoff, worker concurrency). Zero fields fall back to package
	// defaults.
	DNS dns.Options
	// WhoisQueue bounds the channel feeding the serial WHOIS consumer.
	// It is the backpressure valve: when it fills up, the DNS pre-check
	// workers block instead of ballooning memory on huge dictionaries.
	// Zero falls back to DefaultWhoisQueue.
	WhoisQueue int
	// ForceDNSOnly skips WHOIS entirely; set interactively after the user
	// confirms an unconfigured TLD.
	ForceDNSOnly bool

	// ForceWhois un-degrades a previously degraded task on resume: if the
	// task has a NIC configured, WhoisDisabled is cleared so WHOIS is retried.
	// Has no effect on a fresh (non-resumed) task.
	ForceWhois bool

	// Dictionary generator (-gen): write every WordLen-length combination
	// of Charset into <DataDir>/dict/<OutName> and exit.
	Gen     bool
	Charset string
	WordLen int
	OutName string

	Whois whois.Options

	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

const separator = "****************"

// DefaultWhoisQueue bounds the channel between the DNS worker pool and the
// serial WHOIS consumer. It is the backpressure valve that keeps memory
// O(queueCap) instead of O(pending WHOIS work) on huge dictionaries.
const DefaultWhoisQueue = 512

// Run executes the tool. It returns ErrInterrupted if ctx was cancelled; in
// every error path all progress written so far is already persisted on disk.
func Run(ctx context.Context, opts Options) error {
	if opts.DataDir == "" {
		opts.DataDir = "."
	}
	if opts.Stdin == nil {
		opts.Stdin = os.Stdin
	}
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	printf := func(format string, args ...any) { fmt.Fprintf(opts.Stdout, format+"\n", args...) }
	eprintf := func(format string, args ...any) { fmt.Fprintf(opts.Stderr, format+"\n", args...) }
	// printf/eprintf may be called concurrently: DNS pre-check workers
	// print verdicts while the WHOIS consumer prints its own, and both
	// write warnings. A single mutex keeps lines whole (one Write per
	// line into the same bytes.Buffer/os.File) — without it, -race and
	// interleaved terminal output corrupt lines.
	var printMu sync.Mutex
	printf = func(format string, args ...any) {
		printMu.Lock()
		defer printMu.Unlock()
		fmt.Fprintf(opts.Stdout, format+"\n", args...)
	}
	eprintf = func(format string, args ...any) {
		printMu.Lock()
		defer printMu.Unlock()
		fmt.Fprintf(opts.Stderr, format+"\n", args...)
	}

	resultDir := filepath.Join(opts.DataDir, "result") // kept relative like the Python tool
	stateDir := filepath.Join(opts.DataDir, "state")   // resume checkpoints live apart from results
	if err := os.MkdirAll(resultDir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", resultDir, err)
	}
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", stateDir, err)
	}

	if opts.Gen {
		return generateDict(opts, printf, eprintf)
	}

	if opts.ListTLDs || opts.ListDicts {
		return listOnly(opts, printf)
	}

	registry, err := config.Load(config.DefaultPath(opts.DataDir))
	if err != nil {
		return err
	}

	var task *state.Task

	switch {
	case opts.Resume != "":
		task, err = pickResumable(opts, printf)
	case !opts.Interactive:
		task, err = startNewTask(ctx, opts, registry, resultDir, printf, eprintf)
	default:
		task, err = interactiveStart(ctx, opts, registry, resultDir, printf, eprintf)
	}
	if err != nil {
		return err
	}

	// When resuming, refresh the WHOIS configuration from the current
	// tld.json: servers/marker strings may have been corrected since the
	// task started. Dictionary choice and existing progress are untouched.
	//
	// -force-whois additionally un-degrades a task that had fallen back to
	// DNS-only mode (the TLD must still have a working WHOIS config).
	if opts.Resume != "" && task.NIC != "" {
		dirty := false
		if opts.ForceWhois && task.WhoisDisabled {
			printf("note: -force-whois re-enabling WHOIS for this task (was degraded to DNS-only)")
			task.WhoisDisabled = false
			dirty = true
		}
		if !task.WhoisDisabled {
			if entry, lerr := registry.Lookup(task.TLD); lerr == nil &&
				(entry.NIC != task.NIC || entry.Response != task.ResponseMark) {
				printf("note: refreshed WHOIS config from tld.json (server %s -> %s)", task.NIC, entry.NIC)
				task.NIC = entry.NIC
				task.ResponseMark = entry.Response
				dirty = true
			}
		}
		if dirty {
			if serr := task.SaveMeta(); serr != nil {
				eprintf("WARN could not save refreshed state: %v", serr)
			}
		}
	}

	return runLoop(ctx, opts, task, printf, eprintf)
}

func listOnly(opts Options, printf func(string, ...any)) error {
	if opts.ListTLDs {
		reg, err := config.Load(config.DefaultPath(opts.DataDir))
		if err != nil {
			return err
		}
		printf("Available TLDs: %s", strings.Join(reg.TLDs(), ", "))
	}
	if opts.ListDicts {
		names := dict.List(opts.DataDir)
		if len(names) == 0 {
			printf("No dictionaries found in %s", opts.DataDir+"/dict")
		} else {
			printf("Available dicts: %s", strings.Join(names, ", "))
		}
	}
	return nil
}

// startNewTask validates flags and builds a fresh task (non-interactive mode).
func startNewTask(ctx context.Context, opts Options, registry *config.Registry, resultDir string,
	printf, eprintf func(string, ...any)) (*state.Task, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if opts.TLD == "" || opts.DictName == "" {
		return nil, fmt.Errorf("-tld and -dict are required in non-interactive mode")
	}
	entry, lookupErr := registry.Lookup(opts.TLD)
	dnsOnly := opts.ForceDNSOnly || lookupErr != nil
	if dnsOnly && !opts.ForceDNSOnly {
		printf("")
		printf("================================================================")
		printf("[!] WARNING: TLD %q is NOT configured in tld.json.", opts.TLD)
		printf("[!] The scan will judge availability ONLY by DNS NS records.")
		printf("[!] This is NOT fully reliable: registered-but-undelegated domains look available.")
		printf("    Configured TLDs: %s", strings.Join(registry.TLDs(), ", "))
		printf("================================================================")
		printf("")
	}
	nic, mark := "", ""
	if !dnsOnly {
		nic, mark = entry.NIC, entry.Response
	}
	dictPath := dict.Path(opts.DataDir, opts.DictName)
	total, err := dict.Open(dictPath).Count()
	if err != nil {
		return nil, err
	}
	if total == 0 {
		return nil, fmt.Errorf("%s: dictionary is empty", dictPath)
	}
	if opts.DelaySecs < 0 {
		return nil, fmt.Errorf("delay must be >= 0")
	}
	start := time.Now()
	logPath := state.LogPath(resultDir, strings.ToLower(opts.TLD), opts.DictName, start)
	sp := state.StatePath(filepath.Join(opts.DataDir, "state"), strings.ToLower(opts.TLD), opts.DictName, start)
	task, err := state.New(state.Config{
		TLD:          strings.ToLower(opts.TLD),
		DictName:     opts.DictName,
		DictPath:     dictPath,
		NIC:          nic,
		ResponseMark: mark,
		DelaySeconds: opts.DelaySecs,
		LogPath:      logPath,
		StatePath:    sp,
		JournalPath:  state.JournalPath(sp),
		Total:        total,
	})
	if err != nil {
		return nil, err
	}
	if dnsOnly {
		task.WhoisDisabled = true
		if err := task.SaveMeta(); err != nil {
			return nil, err
		}
	}
	return task, nil
}

// interactiveStart reproduces the original prompt flow, extended with a
// resume menu for interrupted tasks.
func interactiveStart(ctx context.Context, opts Options, registry *config.Registry, resultDir string,
	printf, eprintf func(string, ...any)) (*state.Task, error) {

	in := bufio.NewScanner(opts.Stdin)

	// Resume menu: offer unfinished tasks first, if any.
	paths, tasks, err := state.Resumable(filepath.Join(opts.DataDir, "state"))
	if err != nil {
		eprintf("note: could not scan %s for resumable tasks: %v", resultDir, err)
	}
	if len(tasks) > 0 {
		printf("")
		printf("Found unfinished task(s):")
		for i, t := range tasks {
			line := fmt.Sprintf("  [%d] %s/%s  checked:%d/%d failed:%d",
				i+1, t.TLD, t.DictName, t.CheckedCount(), t.Total, len(t.Failed))
			if c, cerr := t.Counts(); cerr == nil {
				line += fmt.Sprintf(" available:%d unavailable:%d redemption:%d pending-delete:%d pending:%d",
					c.Available, c.Unavailable, c.Redemption, c.PendingDelete, c.Pending)
			}
			printf("%s", line)
		}
		printf("Enter a number to resume that task, or press Enter to start a new one:")
		for {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			line, ok := readLine(in)
			if !ok {
				return nil, io.ErrUnexpectedEOF
			}
			line = strings.TrimSpace(line)
			if line == "" {
				break // start new
			}
			n, convErr := strconv.Atoi(line)
			if convErr == nil && n >= 1 && n <= len(tasks) {
				t, loadErr := state.Load(paths[n-1])
				if loadErr != nil {
					return nil, loadErr
				}
				printf("Resuming %s_%s (%d of %d domains checked)", t.TLD, t.DictName, t.CheckedCount(), t.Total)
				return t, nil
			}
			printf("Please enter 1-%d, or an empty line for a new task.", len(tasks))
		}
	}

	// New task prompts (same three questions as the Python version, plus a
	// DNS-only confirmation for TLDs missing from tld.json).
	var tld string
	tldDNSOnly := false
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		fmt.Fprint(opts.Stdout, "Enter tld name: ")
		ok2 := in.Scan()
		if !ok2 {
			fmt.Fprintln(opts.Stdout)
			return nil, io.ErrUnexpectedEOF
		}
		s := strings.ToLower(strings.TrimSpace(in.Text()))
		if s == "" {
			printf("Invalid input: tld must not be empty")
			continue
		}
		if _, err := registry.Lookup(s); err == nil {
			tld = s
			break
		}
		printf("[!] TLD %q is not configured in tld.json; available: %s", s, strings.Join(registry.TLDs(), ", "))
		printf("    Scan it using ONLY DNS NS records (NOT fully reliable)? [y/N]: ")
		if !in.Scan() {
			return nil, io.ErrUnexpectedEOF
		}
		switch strings.ToLower(strings.TrimSpace(in.Text())) {
		case "y", "yes":
			tld = s
			tldDNSOnly = true
		default:
			continue
		}
		break
	}

	dictName := askValidated(ctx, in, opts.Stdout, printf, "Enter dict name: ", func(s string) (string, error) {
		s = strings.TrimSpace(s)
		if s == "" {
			return "", errors.New("dict name must not be empty")
		}
		p := dict.Path(opts.DataDir, s)
		if _, err := os.Stat(p); err != nil {
			return "", fmt.Errorf("dict not found in %s; available: %s",
				filepath.Join(opts.DataDir, "dict"), strings.Join(dict.List(opts.DataDir), ", "))
		}
		return s, nil
	})

	delayStr := askValidated(ctx, in, opts.Stdout, printf, "Enter delay [0]: ", func(s string) (string, error) {
		s = strings.TrimSpace(s)
		if s == "" {
			return "0", nil
		}
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			return "", errors.New("delay must be a non-negative integer (seconds)")
		}
		return strconv.Itoa(n), nil
	})
	delay, _ := strconv.Atoi(delayStr)

	newOpts := opts
	newOpts.TLD, newOpts.DictName, newOpts.DelaySecs = tld, dictName, delay
	newOpts.ForceDNSOnly = tldDNSOnly
	return startNewTask(ctx, newOpts, registry, resultDir, printf, eprintf)
}

// runLoop performs the actual scanning with full state persistence, using
// a two-queue pipeline:
//
//	dictionary ──► DNS worker pool (N parallel NS pre-checks) ──► bounded
//	queue ──► serial WHOIS consumer (rate-limited exactly as before)
//
// The DNS pool runs ahead fast (opts.DNS.Concurrency workers); the WHOIS
// side stays strictly serial to preserve the anti-crawl pacing. The queue
// is bounded so backpressure — not memory — absorbs the speed mismatch on
// multi-million-entry dictionaries. Concurrency only multiplies the
// DNS-side throughput; WHOIS behavior (makeup waits, backoff, degradation,
// delay jitter) is byte-for-byte the same logic as the old serial loop.
//
// The dictionary is streamed from task.DictPath so a resumed session
// always reflects the current file; its entry count must match the
// recorded total.
//
// Per-domain flow:
//  1. DNS NS pre-check (worker pool) — NS records prove registration,
//     skipping WHOIS entirely; DNS-uncertain domains fall into the queue.
//  2. WHOIS query (serial consumer, retries/backoff) unless disabled.
//  3. If WHOIS exhausts its retries (anti-crawl), the task degrades to
//     DNS-only judgment for everything that follows; the flag persists so
//     resumed sessions stay degraded.
func runLoop(ctx context.Context, opts Options, task *state.Task,
	printf, eprintf func(string, ...any)) error {

	prefixes := dict.Open(task.DictPath)
	defer prefixes.Close()
	total, err := prefixes.Count()
	if err != nil {
		return err
	}
	if total != task.Total {
		return fmt.Errorf("dictionary %s changed since the task started: %d entries now, %d recorded",
			task.DictPath, total, task.Total)
	}
	defer task.CloseJournal()

	// Retry notices from the whois/dns clients go to stderr as warnings.
	warnOpts := opts.Whois
	warnOpts.Logf = func(format string, args ...any) { eprintf("WARN "+format, args...) }
	client := whois.NewClient(warnOpts)
	dnsOpts := opts.DNS
	dnsOpts.Logf = func(format string, args ...any) { eprintf("WARN dns "+format, args...) }
	nsChecker, err := dns.New(dnsOpts)
	if err != nil {
		return fmt.Errorf("invalid DNS resolver configuration: %w", err)
	}

	if task.NIC == "" {
		task.WhoisDisabled = true // task created without a WHOIS configuration
	}

	logF, err := openLog(task.LogPath)
	if err != nil {
		return err
	}
	defer logF.Close()
	logFile := bufio.NewWriter(logF)
	defer logF.Sync()

	sess, err := task.BeginSession()
	if err != nil {
		return err
	}
	if !task.HeaderWritten {
		header := fmt.Sprintf("TLD: %s Dict: %s Delay: %d Time: %s",
			task.TLD, task.DictName, task.DelaySeconds, time.Now().Format("2006-01-02-15-04-05"))
		fmt.Fprintln(logFile, header)
		fmt.Fprintln(logFile, separator)
		task.HeaderWritten = true
	} else {
		fmt.Fprintf(logFile, "-- resumed at %s (from entry %d/%d) --\n",
			time.Now().Format("2006-01-02-15-04-05"), sess.Start+1, task.Total)
	}
	logFile.Flush()
	if err := task.SaveMeta(); err != nil {
		eprintf("WARN could not save state: %v", err)
	}

	printf("Task Start")
	if task.WhoisDisabled {
		printf("[!] DNS-NS-only mode: results are NOT fully reliable.")
		printf("[!] Registered-but-undelegated domains look available under this mode.")
	}
	printf(separator)

	interrupted := false
	degradedAnnounced := false

	// lastWhoisDone records when the previous WHOIS query to the NIC
	// completed (zero value means no WHOIS has run yet this session). It
	// drives the pre-query "makeup wait": instead of sleeping a fixed
	// -delay after every WHOIS query, the next WHOIS query is paced
	// relative to this timestamp so that DNS pre-checks and DNS-only
	// verdicts that ran in between overlap the WHOIS cooldown rather than
	// stacking on top of it. In-memory only; a fresh resume starts with no
	// history (resumes are typically long after the last query anyway).
	var lastWhoisDone time.Time

	// Expiry-phase log (<tld>_<dict>_<time>.expiring.log): redemption and
	// pending-delete domains go here, apart from the available-only main
	// log. Opened lazily on the first verdict; a scan that finds none
	// never creates the file. expiringHasContent tracks whether the file
	// carries (or already carried, from a previous session) any entries,
	// which decides whether the "Task Done" footer is appended.
	expiringPath := state.ExpiringLogPath(task.LogPath)
	var expiringF *os.File
	var expiringW *bufio.Writer
	expiringHasContent := false
	if fi, err := os.Stat(expiringPath); err == nil && fi.Size() > 0 {
		expiringHasContent = true // previous session left entries behind
	}
	expiringOpen := func() *bufio.Writer {
		if expiringW != nil {
			return expiringW
		}
		f, err := openLog(expiringPath)
		if err != nil {
			eprintf("WARN could not open %s: %v", expiringPath, err)
			return nil
		}
		w := bufio.NewWriter(f)
		expiringF, expiringW = f, w
		// Header only for a fresh file: on resume the previous session's
		// entries are already there and must not get a second header.
		if fi, serr := os.Stat(expiringPath); serr != nil || fi.Size() == 0 {
			fmt.Fprintf(w, "TLD: %s Dict: %s Delay: %d Time: %s",
				task.TLD, task.DictName, task.DelaySeconds, time.Now().Format("2006-01-02-15-04-05"))
			fmt.Fprintln(w)
			fmt.Fprintln(w, separator)
		}
		return w
	}
	defer func() {
		if expiringW != nil {
			expiringW.Flush()
			expiringF.Sync()
			expiringF.Close()
		}
	}()

	// checkDomain helpers run on the DNS worker pool (precheckDNS) or the
	// serial WHOIS consumer (judgeWhois). Verdicts are recorded via persist
	// (Record + SaveMeta), both concurrency-safe in the v3 state model.

	// expiring log writer — only the WHOIS consumer writes it (single
	// goroutine), so no extra locking is needed.
	persist := func(i int, domain string, status state.Status, errMsg string) {
		rerr := task.Record(i, domain, status, errMsg, 1)
		if rerr == nil {
			rerr = task.SaveMeta()
		}
		if rerr != nil {
			eprintf("WARN could not save state: %v", rerr)
		}
	}

	// dnsPrecheck resolves the NS question for one domain. It returns
	// (nsHit, dnsKnown): dnsKnown=false means the lookup failed (nothing
	// could be concluded).
	dnsPrecheck := func(domain string) (nsHit, dnsKnown bool) {
		nsHit, nsErr := nsChecker.HasNS(ctx, domain)
		if nsErr != nil {
			if ctx.Err() == nil { // Ctrl+C: no need to warn
				eprintf("WARN dns lookup failed for %s: %v", domain, nsErr)
			}
			return false, false
		}
		return nsHit, true
	}

	// judgeWhois runs one domain through WHOIS (skipped when disabled).
	// It returns (ok, usedWhois): ok=false means ctx was cancelled mid-
	// flight and nothing was recorded; usedWhois=false means the verdict
	// came purely from DNS (WHOIS disabled) and no WHOIS pacing applies.
	judgeWhois := func(i int, domain string, dnsKnown bool) (bool, bool) {

		// WHOIS skipped entirely when disabled/unconfigured (DNS-only
		// fallback for queued domains).
		if task.WhoisDisabled {
			if !dnsKnown {
				eprintf("WARN %s cannot be judged (dns lookup failed, whois disabled)", domain)
				persist(i, domain, state.StatusFailed, "dns lookup failed and whois is disabled")
				return true, false
			}
			printf("%s is available [dns, uncertain]", domain)
			fmt.Fprintf(logFile, "%s is available [dns]\n", domain)
			logFile.Flush()
			persist(i, domain, state.StatusAvailableDNS, "")
			return true, false
		}

		// WHOIS rate limiting is a pre-query makeup wait, not a post-query
		// fixed sleep: pace this query relative to when the previous WHOIS
		// query completed, so the DNS pre-check above and any DNS-only
		// verdicts since the last WHOIS overlap the cooldown instead of
		// being serialized after it. The target gap is jittered per query
		// (same ±25% scheme as before); only the residual is slept.
		if wait := whoisMakeupWait(lastWhoisDone, time.Duration(task.DelaySeconds)*time.Second); wait > 0 {
			select {
			case <-ctx.Done():
				return false, false
			case <-time.After(wait):
			}
		}

		resp, qerr := client.Query(ctx, domain, task.NIC)
		lastWhoisDone = time.Now()           // a WHOIS request was issued; pace the next one off this
		if qerr != nil && ctx.Err() != nil { // Ctrl+C during the query
			return false, false
		}
		if qerr != nil {
			// Retries exhausted against this server. Hammering it further
			// is pointless, so degrade the WHOLE task to DNS-only mode;
			// WhoisDisabled persists across resume.
			task.WhoisDisabled = true
			if !degradedAnnounced {
				degradedAnnounced = true
				printf(separator)
				printf("[!] WHOIS server %s rejected every attempt.", task.NIC)
				printf("[!] Falling back to DNS-NS-only mode for the rest of this scan.")
				printf("[!] Those results are NOT fully reliable.")
				printf(separator)
			}
			eprintf("WARN %s failed permanently: %v", domain, qerr)

			if dnsKnown {
				printf("%s is available [dns, uncertain]", domain)
				fmt.Fprintf(logFile, "%s is available [dns]\n", domain)
				logFile.Flush()
				persist(i, domain, state.StatusAvailableDNS, "")
			} else {
				// Even DNS was unreachable: retryable on resume.
				persist(i, domain, state.StatusFailed, qerr.Error())
			}
			return true, true // the whois server WAS contacted (that's why we degraded)
		}

		if strings.Contains(strings.ToLower(resp), strings.ToLower(task.ResponseMark)) {
			printf("%s is available", domain)
			fmt.Fprintf(logFile, "%s is available\n", domain)
			logFile.Flush()
			persist(i, domain, state.StatusAvailable, "")
		} else if hasMark(resp, "redemptionperiod") {
			// EPP redemptionPeriod: still registered but in the 30-day
			// redemption grace period. It cannot be re-registered right
			// now, but will drop if the current owner does not restore it.
			printf("%s is in redemption period (NOT available)", domain)
			if w := expiringOpen(); w != nil {
				fmt.Fprintf(w, "%s is in redemption period (NOT available)\n", domain)
				w.Flush()
				expiringHasContent = true
			}
			persist(i, domain, state.StatusRedemption, "")
		} else if hasMark(resp, "pendingdelete") {
			// EPP pendingDelete: final ~5 days before the domain drops and
			// becomes registerable again.
			printf("%s is pending delete (NOT available)", domain)
			if w := expiringOpen(); w != nil {
				fmt.Fprintf(w, "%s is pending delete (NOT available)\n", domain)
				w.Flush()
				expiringHasContent = true
			}
			persist(i, domain, state.StatusPendingDelete, "")
		} else {
			printf("%s is NOT available", domain)
			persist(i, domain, state.StatusUnavailable, "")
		}
		return true, true // authoritative answer from the whois server
	}

	// ---- two-queue pipeline ----
	//
	// queueItem is what the DNS pool hands to the WHOIS consumer: a
	// domain whose NS pre-check came back empty (or failed). NS hits and
	// DNS-only verdicts are settled right inside the workers.
	type queueItem struct {
		index    int
		domain   string
		dnsKnown bool // false = the pre-check itself failed
	}

	queueCap := opts.WhoisQueue
	if queueCap <= 0 {
		queueCap = DefaultWhoisQueue
	}
	queue := make(chan queueItem, queueCap)

	producerDone := make(chan struct{})
	var producerErr error
	var producerErrMu sync.Mutex

	// Producer: stream the dictionary through the DNS worker pool. Each
	// worker paces its own queries with the full -dns-interval (per-worker
	// semantics — 5 workers ≈ 5x DNS throughput; the shared resolver list
	// is round-robin so they spread across servers).
	workers := opts.DNS.Concurrency
	if workers <= 0 {
		workers = dns.DefaultConcurrency
	}

	// DNS worker pacing: each worker sleeps the full -dns-interval after
	// a pre-check, independent of the others (per-worker semantics — N
	// workers ≈ N QPS). This replaced the old single-loop post-verdict
	// sleep, which had to sit inside the loop because there was only one
	// goroutine.
	paceAfterPrecheck := func() bool { // returns false when interrupted
		if wait := opts.DNS.BaseDelay; wait > 0 {
			select {
			case <-ctx.Done():
				return false
			case <-time.After(wait):
			}
		}
		return true
	}

	go func() {
		defer close(producerDone)
		sem := make(chan struct{}, workers)
		var wg sync.WaitGroup
		for i := sess.Start; i < task.Total; i++ {
			// Checkpoint: stop feeding when interrupted or when the
			// consumer died (e.g. dictionary read error).
			if ctx.Err() != nil {
				break
			}
			if sess.ShouldSkip(i) {
				continue
			}
			domain, derr := prefixes.At(i)
			if derr != nil {
				// The dictionary shrank below its recorded total mid-run:
				// the on-disk state stays valid; the count check reports
				// the mismatch on resume.
				producerErrMu.Lock()
				producerErr = fmt.Errorf("read dictionary entry %d: %w", i, derr)
				producerErrMu.Unlock()
				break
			}
			domain += "." + task.TLD

			sem <- struct{}{}
			wg.Add(1)
			go func(i int, domain string) {
				defer wg.Done()
				defer func() { <-sem }()

				nsHit, dnsKnown := dnsPrecheck(domain)
				if ctx.Err() != nil {
					return // interrupted mid-lookup: nothing recorded
				}
				if nsHit {
					printf("%s is NOT available [dns]", domain)
					persist(i, domain, state.StatusUnavailableDNS, "")
					paceAfterPrecheck() // per-worker resolver cooldown
					return
				}
				// DNS-uncertain (or lookup failed): hand to WHOIS. A
				// full queue blocks here — backpressure keeps memory
				// bounded on multi-million-entry dictionaries. No extra
				// sleep: this item's verdict will be paced by the WHOIS
				// consumer's makeup wait, and the next pre-check starts
				// as soon as the semaphore slot frees.
				select {
				case queue <- queueItem{index: i, domain: domain, dnsKnown: dnsKnown}:
				case <-ctx.Done():
				}
			}(i, domain)
		}
		wg.Wait()
		close(queue)
	}()

	// Consumer: the serial WHOIS judge. Everything about WHOIS pacing is
	// untouched — pre-query makeup wait, exponential backoff, degradation.
	// It exits when the queue is closed and drained, or on cancellation.
	// On cancellation any still-queued items are dropped: the producer
	// stops soon after (its ctx check) and the process is exiting anyway.
	for item := range queue {
		if ctx.Err() != nil {
			interrupted = true
			continue // drain without querying: record nothing
		}
		ok, _ := judgeWhois(item.index, item.domain, item.dnsKnown)
		if !ok {
			interrupted = true
			break
		}
	}

	// Interrupt bookkeeping: a producer break on ctx also counts.
	if ctx.Err() != nil {
		interrupted = true
	}
	if producerErr != nil {
		// Drain result: surface the dictionary error (matches the old
		// abort-on-shrunk-dict behavior).
		producerErrMu.Lock()
		perr := producerErr
		producerErrMu.Unlock()
		<-producerDone
		return perr
	}
	// Wait for the producer to finish (it closes the queue; the consumer
	// above already exited its range, so just reap the goroutine).
	<-producerDone

	// Persist whatever we have before reporting.
	if err := task.SaveMeta(); err != nil {
		eprintf("WARN could not save final state: %v", err)
	}

	counts, cerr := task.Counts()
	if cerr != nil {
		return cerr
	}

	if interrupted {
		printf(separator)
		printf("****Task Interrupted (progress saved)****")
		printf("Progress: %d/%d checked — %d available (%d uncertain-dns), %d NOT available (%d dns, %d redemption, %d pending-delete), %d failed, %d remaining",
			counts.Checked, task.Total,
			counts.Available+counts.AvailableDNS, counts.AvailableDNS,
			counts.Unavailable+counts.UnavailableDNS+counts.Redemption+counts.PendingDelete,
			counts.UnavailableDNS, counts.Redemption, counts.PendingDelete,
			counts.Failed, counts.Failed+counts.Pending)
		printf("Resume later with: -resume=%s", task.MetaPath())
		return ErrInterrupted
	}

	fmt.Fprintln(logFile, separator+" Task Done")
	logFile.Flush()

	// The expiring log gets the same footer when the scan completed. The
	// file may exist from a previous session even if no verdict was found
	// in this one, hence the has-content check rather than writer != nil.
	if expiringW != nil || expiringHasContent {
		if w := expiringOpen(); w != nil {
			fmt.Fprintln(w, separator+" Task Done")
			w.Flush()
		}
	}

	printf(separator)
	printf("Task Done: %d domains — %d available (%d uncertain-dns), %d NOT available (%d via-dns, %d redemption, %d pending-delete), %d failed",
		task.Total,
		counts.Available+counts.AvailableDNS, counts.AvailableDNS,
		counts.Unavailable+counts.UnavailableDNS+counts.Redemption+counts.PendingDelete,
		counts.UnavailableDNS, counts.Redemption, counts.PendingDelete,
		counts.Failed)
	if task.Done() {
		// Nothing left to resume: remove the checkpoint files entirely.
		task.CloseJournal()
		if rerr := os.Remove(task.MetaPath()); rerr != nil && !os.IsNotExist(rerr) {
			eprintf("WARN could not remove %s: %v", task.MetaPath(), rerr)
		}
		if rerr := os.Remove(task.JournalPath()); rerr != nil && !os.IsNotExist(rerr) {
			eprintf("WARN could not remove %s: %v", task.JournalPath(), rerr)
		}
	}
	if task.WhoisDisabled {
		printf("[!] This scan included DNS-NS-only judgments; treat [dns] results with care.")
	}
	if counts.Failed > 0 {
		printf("Some domains could not be judged after exhausting retries.")
		printf("Re-run with -resume=%s to retry only those.", task.MetaPath())
	}
	return nil
}

// whoisMakeupWait returns the residual wait before the next WHOIS query,
// given when the previous WHOIS query completed. It returns 0 when:
//   - there was no prior WHOIS query this session (lastDone is zero — the
//     first query, or a fresh resume), so the first WHOIS goes out at once;
//   - the configured delay is zero (rate limiting disabled), preserving the
//     original tool's "fire as fast as possible" behavior;
//   - enough time has already elapsed since the last WHOIS completion that
//     the (jittered) target gap is already satisfied — this is the overlap
//     win: DNS pre-checks and DNS-only verdicts that ran in between count
//     against the cooldown, so we only sleep the remainder.
//
// The target gap is jittered per query with the same ±25% scheme as
// jitteredDelay, drawn from [0.75*base, 1.25*base].
func whoisMakeupWait(lastDone time.Time, base time.Duration) time.Duration {
	if base <= 0 || lastDone.IsZero() {
		return 0
	}
	target := jitteredDelay(base)
	if elapsed := time.Since(lastDone); elapsed < target {
		return target - elapsed
	}
	return 0
}

// jitteredDelay randomizes the inter-query wait around the configured base:
// uniformly drawn from [base-base/4, base+base/4]. A fixed cadence is easy
// for rate limiters to spot (and boring); a little jitter keeps the pacing
// human-ish while staying close to the requested delay.
func jitteredDelay(base time.Duration) time.Duration {
	if base <= 0 {
		return 0
	}
	spread := base / 4
	low := base - spread
	return low + time.Duration(rand.Int64N(int64(2*spread)+1))
}

// hasMark reports whether the WHOIS response contains the given marker
// string, case-insensitively: EPP status codes like "redemptionPeriod" and
// plain text like "Redemption Period" both match "redemptionperiod".
func hasMark(resp, mark string) bool {
	return strings.Contains(strings.ToLower(resp), strings.ToLower(mark))
}

func openLog(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open log %s: %w", path, err)
	}
	return f, nil
}

// pickResumable resolves the -resume flag to a concrete task.
func pickResumable(opts Options, printf func(string, ...any)) (*state.Task, error) {
	sel := strings.TrimSpace(opts.Resume)
	switch strings.ToLower(sel) { // keywords are case-insensitive; paths must keep their case
	case "", "latest", "true", "yes", "y":
		_, tasks, err := state.Resumable(filepath.Join(opts.DataDir, "state"))
		if err != nil {
			return nil, err
		}
		if len(tasks) == 0 {
			return nil, fmt.Errorf("no unfinished tasks found in %s", filepath.Join(opts.DataDir, "state"))
		}
		t := tasks[0]
		printf("Resuming %s_%s (%d of %d domains checked)", t.TLD, t.DictName, t.CheckedCount(), t.Total)
		return t, nil
	default:
		t, err := state.Load(sel)
		if err != nil {
			return nil, err
		}
		printf("Resuming %s_%s (%d of %d domains checked)", t.TLD, t.DictName, t.CheckedCount(), t.Total)
		return t, nil
	}
}

// askValidated loops until validator accepts the input or ctx is cancelled.
func askValidated[T any](ctx context.Context, in *bufio.Scanner, out io.Writer,
	printf func(string, ...any), label string, validate func(string) (T, error)) T {

	var zero T
	for {
		if err := ctx.Err(); err != nil {
			return zero
		}
		fmt.Fprintf(out, "%s", label)
		if !in.Scan() {
			fmt.Println()
			return zero // EOF / closed stdin
		}
		val, err := validate(in.Text())
		if err == nil {
			return val
		}
		fmt.Fprintf(out, "Invalid input: %v\n", err)
		if ctx.Err() != nil {
			return zero
		}
	}
}

func readLine(in *bufio.Scanner) (string, bool) {
	if !in.Scan() {
		return "", false
	}
	return in.Text(), true
}
