// Command DomainCheck is a Go rewrite of the original Python domain
// scanner. It keeps the interactive workflow, the tld.json registry and the
// dict/ + result/ layout, but adds:
//
//   - crash-safe state: progress is persisted atomically after every domain,
//     and interrupted or partially failed tasks can be resumed (-resume);
//   - retries with exponential backoff for every WHOIS query;
//   - graceful handling of Ctrl+C/SIGTERM (state saved instead of data loss).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"time"

	"github.com/uselibrary/DomainCheck/internal/app"
	"github.com/uselibrary/DomainCheck/internal/dns"
	"github.com/uselibrary/DomainCheck/internal/whois"
)

func main() {
	var (
		opts app.Options

		dataDir     = flag.String("data", ".", "data directory containing tld.json, dict/ and result/")
		tld         = flag.String("tld", "", "TLD to scan (skips interactive prompt)")
		dictName    = flag.String("dict", "", "dictionary name inside dict/ (skips interactive prompt)")
		delay       = flag.Int("delay", 0, "delay between queries in seconds")
		resume      = flag.String("resume", "", "resume an unfinished task: 'latest' or a path to a *.state.json file")
		dnsServer   = flag.String("dns", "", "custom DNS resolver for NS pre-checks, host:port (default: system resolver)")
		genDict     = flag.Bool("gen", false, "generate a dictionary from -charset/-len and exit")
		charset     = flag.String("charset", "", "dictionary generator: candidate characters, e.g. \"abc123\"")
		wordLen     = flag.Int("len", 0, "dictionary generator: length of every entry")
		outName     = flag.String("out", "", "dictionary generator: output file name inside dict/")
		listTLDs    = flag.Bool("list-tlds", false, "list TLDs from tld.json and exit")
		listDicts   = flag.Bool("list-dicts", false, "list dictionaries in dict/ and exit")
		timeout     = flag.Duration("timeout", whois.DefaultTimeout, "per-attempt timeout (WHOIS and DNS lookups)")
		retries     = flag.Int("retries", 3, "WHOIS retries per query after the first attempt")
		interval    = flag.Duration("interval", 10*time.Second, "WHOIS retry interval (exponential backoff base)")
		dnsRetries  = flag.Int("dns-retries", 1, "DNS lookup retries after the first attempt")
		dnsInterval = flag.Duration("dns-interval", time.Second, "DNS retry interval (exponential backoff base, min 100ms)")
		maxBackoff  = flag.Duration("max-backoff", whois.DefaultMaxDelay, "upper bound for both retry backoffs")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "DomainCheck — TLD domain availability scanner (Go rewrite)\n\nFlags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nRun without flags for the interactive flow (same questions as the Python version).\n")
	}
	flag.Parse()

	if *showVersion {
		if info, ok := debug.ReadBuildInfo(); ok {
			fmt.Println("DomainCheck", info.Main.Version)
		} else {
			fmt.Println("DomainCheck (unknown version)")
		}
		return
	}

	opts.DataDir = *dataDir
	opts.TLD = *tld
	opts.DictName = *dictName
	opts.DelaySecs = *delay
	opts.Resume = *resume
	opts.ListTLDs = *listTLDs
	opts.ListDicts = *listDicts
	opts.Gen = *genDict
	opts.Charset = *charset
	opts.WordLen = *wordLen
	opts.OutName = *outName
	if *dnsInterval < 100*time.Millisecond {
		fmt.Fprintln(os.Stderr, "Error: -dns-interval must be at least 100ms")
		os.Exit(2)
	}
	opts.Whois = whois.Options{
		Timeout:    *timeout,
		MaxRetries: *retries,
		BaseDelay:  *interval,
		MaxDelay:   *maxBackoff,
	}
	opts.DNS = dns.Options{
		Server:     *dnsServer,
		Timeout:    *timeout,
		MaxRetries: *dnsRetries,
		BaseDelay:  *dnsInterval,
		MaxDelay:   *maxBackoff,
	}

	// Interactive when the user gave no task-defining flags, mirroring the
	// Python behavior of just running `python3 GetDomain.py`.
	opts.Interactive = *tld == "" && *dictName == "" && *resume == "" &&
		!*listTLDs && !*listDicts && !*genDict

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// After the first signal we cancel gracefully; restore default handling
	// so a second Ctrl+C always terminates immediately.
	go func() {
		<-ctx.Done()
		stop()
	}()

	err := app.Run(ctx, opts)

	switch {
	case err == nil:
	case errors.Is(err, app.ErrInterrupted):
		os.Exit(130)
	default:
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
