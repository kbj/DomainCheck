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
	"strconv"
	"strings"
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
	// backoff). Zero fields fall back to package defaults.
	DNS dns.Options
	// ForceDNSOnly skips WHOIS entirely; set interactively after the user
	// confirms an unconfigured TLD.
	ForceDNSOnly bool

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

	resultDir := opts.DataDir + "/result" // kept relative like the Python tool
	stateDir := opts.DataDir + "/state"   // resume checkpoints live apart from results
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
	if opts.Resume != "" && !task.WhoisDisabled && task.NIC != "" {
		if entry, lerr := registry.Lookup(task.TLD); lerr == nil &&
			(entry.NIC != task.NIC || entry.Response != task.ResponseMark) {
			printf("note: refreshed WHOIS config from tld.json (server %s -> %s)", task.NIC, entry.NIC)
			task.NIC = entry.NIC
			task.ResponseMark = entry.Response
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
	prefixes, err := dict.Load(dictPath)
	if err != nil {
		return nil, err
	}
	if opts.DelaySecs < 0 {
		return nil, fmt.Errorf("delay must be >= 0")
	}
	start := time.Now()
	logPath := state.LogPath(resultDir, strings.ToLower(opts.TLD), opts.DictName, start)
	sp := state.StatePath(opts.DataDir+"/state", strings.ToLower(opts.TLD), opts.DictName, start)
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
		Total:        len(prefixes),
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
	paths, tasks, err := state.Resumable(opts.DataDir + "/state")
	if err != nil {
		eprintf("note: could not scan %s for resumable tasks: %v", resultDir, err)
	}
	if len(tasks) > 0 {
		printf("")
		printf("Found unfinished task(s):")
		for i, t := range tasks {
			line := fmt.Sprintf("  [%d] %s/%s  progress:%d/%d failed:%d",
				i+1, t.TLD, t.DictName, t.Cursor(), t.Total, len(t.Failed))
			if c, cerr := t.Counts(); cerr == nil {
				line += fmt.Sprintf(" available:%d unavailable:%d pending:%d",
					c.Available, c.Unavailable, c.Pending)
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
				printf("Resuming %s_%s (%d of %d domains checked)", t.TLD, t.DictName, t.Cursor(), t.Total)
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
				filepathJoin(opts.DataDir, "dict"), strings.Join(dict.List(opts.DataDir), ", "))
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

func filepathJoin(parts ...string) string { return strings.Join(parts, "/") }

// runLoop performs the actual scanning with full state persistence.
// The dictionary is (re)loaded from task.DictPath so a resumed session
// always reflects the current file; its size must match the recorded total.
//
// Per-domain flow:
//  1. DNS NS pre-check — NS records prove registration, skipping WHOIS.
//  2. WHOIS query (with retries/backoff) unless disabled.
//  3. If WHOIS exhausts its retries (anti-crawl), the task degrades to
//     DNS-only judgment for everything that follows; the flag persists so
//     resumed sessions stay degraded.
func runLoop(ctx context.Context, opts Options, task *state.Task,
	printf, eprintf func(string, ...any)) error {

	prefixes, err := dict.Load(task.DictPath)
	if err != nil {
		return err
	}
	if len(prefixes) != task.Total {
		return fmt.Errorf("dictionary %s changed since the task started: %d entries now, %d recorded",
			task.DictPath, len(prefixes), task.Total)
	}
	defer task.CloseJournal()

	// Retry notices from the whois/dns clients go to stderr as warnings.
	warnOpts := opts.Whois
	warnOpts.Logf = func(format string, args ...any) { eprintf("WARN "+format, args...) }
	client := whois.NewClient(warnOpts)
	dnsOpts := opts.DNS
	dnsOpts.Logf = func(format string, args ...any) { eprintf("WARN dns "+format, args...) }
	nsChecker := dns.New(dnsOpts)

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

	// checkDomain runs the full pipeline for one domain and reports its
	// outcome. Returns false when the context was cancelled mid-flight
	// (caller stops the loop without recording anything).
	// checkDomain runs one domain through DNS pre-check + WHOIS. It returns
	// (ok, usedWhois): ok=false means ctx was cancelled mid-flight and
	// nothing was recorded; usedWhois drives which inter-query delay applies.
	checkDomain := func(i int, domain string) (bool, bool) {
		// Step 1: DNS NS pre-check.
		hasNS, dnsKnown := false, false
		nsHit, nsErr := nsChecker.HasNS(ctx, domain)
		if nsErr != nil {
			if ctx.Err() != nil { // Ctrl+C during the lookup
				return false, false
			}
			eprintf("WARN dns lookup failed for %s: %v", domain, nsErr)
		} else {
			dnsKnown = true
			hasNS = nsHit
		}

		persist := func(status state.Status, errMsg string) {
			rerr := task.Record(i, domain, status, errMsg, 1)
			if rerr == nil {
				rerr = task.SaveMeta()
			}
			if rerr != nil {
				eprintf("WARN could not save state: %v", rerr)
			}
		}

		if hasNS {
			printf("%s is NOT available [dns]", domain)
			persist(state.StatusUnavailableDNS, "")
			return true, false
		}

		// Step 2: WHOIS — skipped entirely when disabled/unconfigured.
		if task.WhoisDisabled {
			if !dnsKnown {
				eprintf("WARN %s cannot be judged (dns lookup failed, whois disabled)", domain)
				persist(state.StatusFailed, "dns lookup failed and whois is disabled")
				return true, false
			}
			printf("%s is available [dns, uncertain]", domain)
			fmt.Fprintf(logFile, "%s is available [dns]\n", domain)
			logFile.Flush()
			persist(state.StatusAvailableDNS, "")
			return true, false
		}

		resp, qerr := client.Query(ctx, domain, task.NIC)
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
				persist(state.StatusAvailableDNS, "")
			} else {
				// Even DNS was unreachable: retryable on resume.
				persist(state.StatusFailed, qerr.Error())
			}
			return true, true // the whois server WAS contacted (that's why we degraded)
		}

		if strings.Contains(strings.ToLower(resp), strings.ToLower(task.ResponseMark)) {
			printf("%s is available", domain)
			fmt.Fprintf(logFile, "%s is available\n", domain)
			logFile.Flush()
			persist(state.StatusAvailable, "")
		} else {
			printf("%s is NOT available", domain)
			persist(state.StatusUnavailable, "")
		}
		return true, true // authoritative answer from the whois server
	}

	for i := sess.Start; i < task.Total; i++ {
		// Indices already settled in earlier sessions are skipped; the
		// skip map covers only [cursor, progress), never the whole dict.
		if sess.ShouldSkip(i) {
			continue
		}
		if ctx.Err() != nil {
			interrupted = true
			break
		}

		domain := prefixes[i] + "." + task.TLD
		ok, usedWhois := checkDomain(i, domain)
		if !ok {
			interrupted = true
			break
		}

		if i == task.Total-1 {
			break // no further query to pace
		}

		// Inter-query pacing depends on where the next request will go:
		// pure DNS judgments keep a small fixed gap; the configured (and
		// jittered) delay only applies when a WHOIS server was involved.
		wait := interQueryDelay(usedWhois, task.DelaySeconds, opts.DNS.BaseDelay)
		if wait <= 0 {
			continue
		}
		select {
		case <-ctx.Done():
			interrupted = true
		case <-time.After(wait):
		}
		if interrupted {
			break
		}
	}

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
		printf("Progress: %d/%d checked — %d available (%d uncertain-dns), %d NOT available (%d dns), %d failed, %d remaining",
			counts.Checked, task.Total,
			counts.Available+counts.AvailableDNS, counts.AvailableDNS,
			counts.Unavailable+counts.UnavailableDNS, counts.UnavailableDNS,
			counts.Failed, counts.Failed+counts.Pending)
		printf("Resume later with: -resume=%s", task.MetaPath())
		return ErrInterrupted
	}

	fmt.Fprintln(logFile, separator+" Task Done")
	logFile.Flush()

	printf(separator)
	printf("Task Done: %d domains — %d available (%d uncertain-dns), %d NOT available (%d via-dns), %d failed",
		task.Total,
		counts.Available+counts.AvailableDNS, counts.AvailableDNS,
		counts.Unavailable+counts.UnavailableDNS, counts.UnavailableDNS,
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

// interQueryDelay picks the wait before the next domain: the configured
// DNS interval (fixed, no jitter) for pure-DNS verdicts, or the configured
// jittered delay when the WHOIS server was involved. A whois delay of 0
// still yields no wait, preserving the original tool's behavior.
func interQueryDelay(usedWhois bool, whoisSecs int, dnsInterval time.Duration) time.Duration {
	if !usedWhois {
		return dnsInterval
	}
	if whoisSecs <= 0 {
		return 0
	}
	return jitteredDelay(time.Duration(whoisSecs) * time.Second)
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
		_, tasks, err := state.Resumable(opts.DataDir + "/state")
		if err != nil {
			return nil, err
		}
		if len(tasks) == 0 {
			return nil, fmt.Errorf("no unfinished tasks found in %s", opts.DataDir+"/state")
		}
		t := tasks[0]
		printf("Resuming %s_%s (%d of %d domains checked)", t.TLD, t.DictName, t.Cursor(), t.Total)
		return t, nil
	default:
		t, err := state.Load(sel)
		if err != nil {
			return nil, err
		}
		printf("Resuming %s_%s (%d of %d domains checked)", t.TLD, t.DictName, t.Cursor(), t.Total)
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
