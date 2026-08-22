// Package dns implements native-Go DNS NS lookups used to pre-check whether
// a domain is registered. It uses net.Resolver with PreferGo so it never
// shells out to dig/nslookup and works cross-platform (Linux, Windows, ...).
package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
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
	// Server optionally overrides the system resolver, "host:port" form
	// (e.g. "1.1.1.1:53"). Empty means use the system configuration.
	Server string
	// Logf receives human-readable retry notices; may be nil.
	Logf func(format string, args ...any)
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

// Checker performs NS lookups with retries and exponential backoff.
type Checker struct {
	resolver *net.Resolver
	opts     Options
}

// New builds a checker. The resolver always uses Go's built-in DNS client
// (PreferGo), so no external tools and no cgo are involved.
func New(opts Options) *Checker {
	opts.applyDefaults()
	r := &net.Resolver{PreferGo: true}
	if opts.Server != "" {
		server := opts.Server
		r.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			conn, err := d.DialContext(ctx, network, server)
			if err != nil {
				return nil, err
			}
			// The conn must keep its concrete type (*net.UDPConn etc.) —
			// wrapping it hides PacketConn/TCP specifics from the resolver.
			// So cancellation closes the conn instead: that aborts any
			// blocking read/write immediately. The watcher's lifetime is
			// bounded by the per-attempt timeout.
			go func() {
				select {
				case <-ctx.Done():
					conn.Close()
				case <-time.After(opts.Timeout + 2*opts.MaxDelay):
				}
			}()
			return conn, nil
		}
	}
	return &Checker{resolver: r, opts: opts}
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
// Transient failures are retried with exponential backoff; cancellation of
// ctx aborts immediately.
func (c *Checker) HasNS(ctx context.Context, domain string) (bool, error) {
	var lastErr error
	for attempt := 0; attempt <= c.opts.MaxRetries; attempt++ {
		if attempt > 0 {
			delay := backoff.Delay(c.opts.BaseDelay, c.opts.MaxDelay, attempt-1)
			if c.opts.Logf != nil {
				c.opts.Logf("dns attempt %d/%d for %s failed (%v); retrying in %v",
					attempt, c.opts.MaxRetries, domain, lastErr, delay.Truncate(time.Millisecond))
			}
			select {
			case <-ctx.Done():
				return false, ctx.Err()
			case <-time.After(delay):
			}
		}

		has, definitive, err := c.lookupOnce(ctx, domain)
		if err != nil && !definitive {
			lastErr = err
			if ctx.Err() != nil {
				return false, fmt.Errorf("dns %s: %w", domain, ctx.Err())
			}
			continue // transient failure: retry
		}
		return has, err // definitive answer (or ctx cancellation inside lookupOnce)
	}
	return false, fmt.Errorf("dns %s: giving up after %d attempt(s): %w",
		domain, c.opts.MaxRetries+1, lastErr)
}

func (c *Checker) lookupOnce(ctx context.Context, domain string) (hasNS bool, definitive bool, err error) {
	attemptCtx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
	defer cancel()

	records, err := c.resolver.LookupNS(attemptCtx, domain)
	if err == nil {
		return len(records) > 0, true, nil
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		// NXDOMAIN / name error: the name has no records at all.
		return false, true, nil
	}
	if attemptCtx.Err() != nil && ctx.Err() == nil {
		return false, false, fmt.Errorf("timeout after %v: %w", c.opts.Timeout, attemptCtx.Err())
	}
	return false, false, err
}
