// Package whois implements a WHOIS (RFC 3912) query client with
// timeout control and automatic retries using exponential backoff.
package whois

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/uselibrary/DomainCheck/internal/backoff"
)

const (
	// DefaultPort is the standard WHOIS port (RFC 3912).
	DefaultPort = 43
	// DefaultTimeout is the default per-attempt deadline.
	DefaultTimeout = 10 * time.Second
	// DefaultMaxRetries is the number of retries after the initial attempt.
	DefaultMaxRetries = 4
	// DefaultBaseDelay is the backoff delay before the first retry.
	DefaultBaseDelay = 1 * time.Second
	// DefaultMaxDelay caps the exponential backoff delay.
	DefaultMaxDelay = 60 * time.Second

	// maxResponseBytes bounds how much data we read from a server to
	// protect against misbehaving hosts.
	maxResponseBytes = 1 << 20 // 1 MiB
)

// Options configures the client. Zero values fall back to the defaults above.
type Options struct {
	// Port overrides the WHOIS TCP port (mainly useful in tests).
	Port int
	// Timeout is the deadline for a single attempt (connect+write+read).
	Timeout time.Duration
	// MaxRetries is how many times a failed attempt is retried.
	MaxRetries int
	// BaseDelay is the delay before the first retry; it doubles on every
	// subsequent retry (exponential backoff) up to MaxDelay.
	BaseDelay time.Duration
	// MaxDelay caps the exponential backoff.
	MaxDelay time.Duration
	// Logf, when non-nil, receives human-readable retry notices.
	Logf func(format string, args ...any)
}

func (o *Options) applyDefaults() {
	if o.Port <= 0 {
		o.Port = DefaultPort
	}
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

// Client queries WHOIS servers.
type Client struct {
	opts Options
}

// NewClient returns a client with defaults applied to opts.
func NewClient(opts Options) *Client {
	opts.applyDefaults()
	return &Client{opts: opts}
}

// Query sends domain to server and returns the raw response text.
//
// A failed attempt (network error, timeout, bad response) is retried up to
// Options.MaxRetries times. The wait between attempts grows exponentially:
// BaseDelay, BaseDelay*2, BaseDelay*4, ... capped at MaxDelay, plus random
// jitter so parallel clients do not synchronize. If the context is cancelled
// the call stops immediately and returns the context error.
func (c *Client) Query(ctx context.Context, domain, server string) (string, error) {
	addr := net.JoinHostPort(server, fmt.Sprint(c.opts.Port))

	var lastErr error
	for attempt := 0; attempt <= c.opts.MaxRetries; attempt++ {
		if attempt > 0 {
			delay := backoff.Delay(c.opts.BaseDelay, c.opts.MaxDelay, attempt-1)
			if c.opts.Logf != nil {
				c.opts.Logf("attempt %d/%d for %s failed (%v); retrying in %v",
					attempt, c.opts.MaxRetries, domain, lastErr, delay.Truncate(time.Millisecond))
			}
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(delay):
			}
		}

		resp, err := func() (string, error) {
			// Bound the WHOLE attempt (connect included) with a context
			// deadline; otherwise a half-open/hanging TCP connect could
			// block far longer than Options.Timeout.
			attemptCtx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
			defer cancel()
			return queryOnce(attemptCtx, addr, domain)
		}()
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return "", fmt.Errorf("query %s: %w", domain, ctx.Err())
		}
	}
	return "", fmt.Errorf("query %s: giving up after %d attempt(s): %w",
		domain, c.opts.MaxRetries+1, lastErr)
}

func queryOnce(ctx context.Context, addr, domain string) (string, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", fmt.Errorf("connect %s: %w", addr, err)
	}
	defer conn.Close()

	// The context carries the per-attempt deadline; mirror it on the socket.
	deadline := time.Now().Add(DefaultTimeout)
	if dl, ok := ctx.Deadline(); ok {
		deadline = dl
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return "", fmt.Errorf("set deadline: %w", err)
	}

	// Context cancellation does not unblock socket I/O by itself; force it by
	// shrinking the deadline as soon as ctx is done.
	unblock := make(chan struct{})
	defer close(unblock)
	go func() {
		select {
		case <-ctx.Done():
			conn.SetDeadline(time.Now())
		case <-unblock:
		}
	}()

	if _, err := io.WriteString(conn, domain+"\r\n"); err != nil {
		return "", fmt.Errorf("send request: %w", err)
	}

	resp, err := io.ReadAll(io.LimitReader(conn, maxResponseBytes))
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}
	if len(resp) == 0 {
		return "", fmt.Errorf("empty response from %s", addr)
	}
	return string(resp), nil
}
