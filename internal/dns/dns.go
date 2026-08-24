// Package dns implements native-Go DNS NS lookups used to pre-check whether
// a domain is registered. It uses net.Resolver with PreferGo so it never
// shells out to dig/nslookup and works cross-platform (Linux, Windows, ...).
//
// Multiple custom resolvers may be configured (plain UDP/TCP, DoT, DoH);
// queries rotate through them round-robin, and each retry automatically
// moves to the next server in the list.
package dns

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/uselibrary/DomainCheck/internal/backoff"
)

const (
	DefaultTimeout    = 5 * time.Second
	DefaultMaxRetries = 1 // extra attempts after the first one
	DefaultBaseDelay  = 1 * time.Second
	DefaultMaxDelay   = 5 * time.Second
)

// Options configures the checker. Zero values fall back to the defaults.
type Options struct {
	// Timeout is the deadline for a single lookup attempt.
	Timeout time.Duration
	// MaxRetries is how many times a failed (not "no record") lookup is retried.
	MaxRetries int
	// BaseDelay/MaxDelay shape the exponential backoff between retries.
	BaseDelay time.Duration
	MaxDelay  time.Duration
	// Servers optionally overrides the system resolver. Each entry follows
	// the syntax documented on parseServerSpec ("udp://", "tcp://",
	// "tls://", "https://" or bare host[:port]). Queries are distributed
	// round-robin across all entries. Empty means use the system resolver.
	Servers []string
	// Logf receives human-readable retry notices; may be nil.
	Logf func(format string, args ...any)

	// insecureTLS skips TLS certificate verification for tls:// and
	// https:// servers. Unexported on purpose: only the in-package tests
	// may enable it, for the self-signed dnstest servers.
	insecureTLS bool
}

func (o *Options) applyDefaults() {
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	if o.MaxRetries < 0 {
		o.MaxRetries = 0
	}
	if o.BaseDelay <= 0 {
		o.BaseDelay = DefaultBaseDelay
	}
	if o.MaxDelay < o.BaseDelay {
		o.MaxDelay = DefaultMaxDelay
	}
}

// Checker performs NS lookups with retries, exponential backoff and
// round-robin distribution over the configured resolvers.
type Checker struct {
	transports []transport
	opts       Options
	next       atomic.Uint64 // round-robin cursor
}

// New builds a checker. All server entries are validated eagerly so bad
// configuration fails at startup instead of poisoning scan results later.
// The resolver for plain DNS always uses Go's built-in client (PreferGo),
// so no external tools and no cgo are involved.
func New(opts Options) (*Checker, error) {
	opts.applyDefaults()
	var trs []transport
	if len(opts.Servers) == 0 {
		trs = []transport{systemTransport{}}
	} else {
		trs = make([]transport, 0, len(opts.Servers))
		for _, entry := range opts.Servers {
			tr, err := parseServerSpec(entry, opts.insecureTLS)
			if err != nil {
				return nil, err
			}
			trs = append(trs, tr)
		}
	}
	return &Checker{transports: trs, opts: opts}, nil
}

// pick returns the next resolver in round-robin order. Advancing on every
// call (including failed ones) spreads both successful queries and retry
// failover evenly across the list.
func (c *Checker) pick() transport {
	n := int(c.next.Add(1)-1) % len(c.transports)
	return c.transports[n]
}

// HasNS reports whether the domain has at least one NS record.
//
// Results:
//   - (true, nil)  : NS records exist -> the domain IS registered.
//   - (false, nil) : no NS records (including NXDOMAIN: the name does not
//     even exist). This does NOT prove the domain is available — registered
//     but undelegated domains have no NS either.
//   - (false, err) : the lookup itself failed after exhausting retries
//     (network problems, SERVFAIL, ...). Nothing can be concluded.
//
// Transient failures are retried with exponential backoff; every attempt —
// initial or retry — goes to the next resolver in round-robin order, which
// doubles as automatic failover. Cancellation of ctx aborts immediately.
func (c *Checker) HasNS(ctx context.Context, domain string) (bool, error) {
	var lastErr error
	for attempt := 0; attempt <= c.opts.MaxRetries; attempt++ {
		tr := c.pick()
		if attempt > 0 {
			delay := backoff.Delay(c.opts.BaseDelay, c.opts.MaxDelay, attempt-1)
			if c.opts.Logf != nil {
				c.opts.Logf("dns attempt %d/%d for %s via %s failed (%v); retrying in %v",
					attempt, c.opts.MaxRetries, domain, tr.describe(), lastErr, delay.Truncate(time.Millisecond))
			}
			select {
			case <-ctx.Done():
				return false, ctx.Err()
			case <-time.After(delay):
			}
		}

		has, definitive, err := c.attemptOnce(ctx, tr, domain)
		if err != nil && !definitive {
			lastErr = err
			if ctx.Err() != nil {
				return false, fmt.Errorf("dns %s: %w", domain, ctx.Err())
			}
			continue // transient failure: retry (on the next resolver)
		}
		return has, err // definitive answer (or ctx cancellation inside the attempt)
	}
	return false, fmt.Errorf("dns %s: giving up after %d attempt(s): %w",
		domain, c.opts.MaxRetries+1, lastErr)
}

// attemptOnce runs a single lookup attempt against tr under the shared
// per-attempt timeout, regardless of which transport backs it.
func (c *Checker) attemptOnce(ctx context.Context, tr transport, domain string) (hasNS bool, definitive bool, err error) {
	attemptCtx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
	defer cancel()

	has, definitive, err := tr.lookupNS(attemptCtx, domain)
	if err != nil {
		err = fmt.Errorf("via %s: %w", tr.describe(), err)
	}
	return has, definitive, err
}
