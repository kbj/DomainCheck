// Server-spec parsing and per-protocol transports for custom resolvers.
//
// Accepted -dns entries (comma-separated list supported upstream):
//
//	udp://host[:port]   plain UDP DNS   (port defaults to 53)
//	tcp://host[:port]   DNS over TCP    (port defaults to 53)
//	tls://host[:port]   DNS over TLS    (port defaults to 853)
//	https://host/path   DNS over HTTPS (RFC 8484); http:// allowed for testing
//	host[:port]         same as udp://
//
// A bare entry without a port gets the scheme default. IPv6 literals must
// be bracketed ([::1]:53).

package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultPlainPort = "53"
	defaultTLSPort   = "853"
	// maxReplyBytes caps DoH bodies; wire replies are inherently capped at
	// 64KiB by their 16-bit length fields.
	maxReplyBytes = 1 << 19
)

type transport interface {
	// lookupNS performs one NS lookup attempt. Semantics match the
	// package contract documented on HasNS / lookupOnce.
	lookupNS(ctx context.Context, domain string) (hasNS bool, definitive bool, err error)
	// describe names the endpoint for logs and error wrapping.
	describe() string
}

// parseServerSpec turns one user-supplied entry into a ready transport.
// insecureTLS is a test hook: it disables certificate verification for
// tls:// and https:// endpoints and must only be set from package tests.
func parseServerSpec(entry string, insecureTLS bool) (transport, error) {
	s := strings.TrimSpace(entry)
	if s == "" {
		return nil, errors.New("empty DNS server")
	}

	scheme, rest := "", s
	if i := strings.Index(s, "://"); i >= 0 {
		scheme, rest = strings.ToLower(s[:i]), s[i+3:]
	}

	switch scheme {
	case "", "udp":
		addr, err := hostPort(rest, defaultPlainPort)
		if err != nil {
			return nil, err
		}
		return &udpTransport{addr: addr}, nil
	case "tcp":
		addr, err := hostPort(rest, defaultPlainPort)
		if err != nil {
			return nil, err
		}
		return &streamTransport{kind: "tcp", addr: addr}, nil
	case "tls":
		addr, err := hostPort(rest, defaultTLSPort)
		if err != nil {
			return nil, err
		}
		host := hostOf(addr)
		return &streamTransport{
			kind: "tls",
			addr: addr,
			conf: &tls.Config{ServerName: host, InsecureSkipVerify: insecureTLS}, //nolint:gosec // test-only hook
		}, nil
	case "https", "http":
		u, err := url.Parse(s)
		if err != nil {
			return nil, fmt.Errorf("invalid DoH URL %q: %w", s, err)
		}
		if u.Host == "" {
			return nil, fmt.Errorf(`invalid DoH URL %q: missing host, e.g. https://example.com/dns-query`, s)
		}
		return &dohTransport{url: s, insecure: insecureTLS}, nil
	default:
		return nil, fmt.Errorf("unsupported DNS scheme %q in %q (want udp://, tcp://, tls:// or https://)", scheme, s)
	}
}

// hostPort adds the default port when none was given, normalizes bare
// IPv6 literals to bracketed form, and rejects malformed literals.
func hostPort(s, defaultPort string) (string, error) {
	if s == "" {
		return "", errors.New("missing host")
	}
	candidate := s
	if !strings.Contains(candidate, ":") {
		candidate = candidate + ":" + defaultPort
	} else if _, _, err := net.SplitHostPort(candidate); err != nil {
		// A colon without a split-able host:port is a bare IPv6 literal.
		candidate = "[" + strings.Trim(candidate, "[]") + "]:" + defaultPort
	}
	host, _, err := net.SplitHostPort(candidate)
	if err != nil {
		return "", fmt.Errorf("invalid host:port %q", s)
	}
	if strings.Contains(host, ":") && net.ParseIP(host) == nil {
		return "", fmt.Errorf("invalid IPv6 literal %q", host)
	}
	return candidate, nil
}

func hostOf(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return host
}

// ---------------------------------------------------------------------------
// System resolver (no explicit server configured).

type systemTransport struct{}

func (systemTransport) describe() string { return "system resolver" }

func (systemTransport) lookupNS(ctx context.Context, domain string) (bool, bool, error) {
	return lookupNSWithResolver(ctx, domain, &net.Resolver{PreferGo: true})
}

// ---------------------------------------------------------------------------
// Plain UDP via net.Resolver with a dial override. The resolver keeps full
// control of the protocol (retransmits, EDNS, TCP fallback on truncation);
// we only redirect its sockets to the chosen address.

type udpTransport struct {
	addr string
}

func (t *udpTransport) describe() string { return "udp " + t.addr }

func (t *udpTransport) lookupNS(ctx context.Context, domain string) (bool, bool, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			conn, err := d.DialContext(ctx, network, t.addr)
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
				case <-time.After(10 * time.Minute):
				}
			}()
			return conn, nil
		},
	}
	return lookupNSWithResolver(ctx, domain, r)
}

func lookupNSWithResolver(ctx context.Context, domain string, r *net.Resolver) (bool, bool, error) {
	attemptCtx, cancel := context.WithTimeout(ctx, resolverAttemptTimeout(ctx))
	defer cancel()

	records, err := r.LookupNS(attemptCtx, domain)
	if err == nil {
		return len(records) > 0, true, nil
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		// NXDOMAIN / name error: the name has no records at all.
		return false, true, nil
	}
	if attemptCtx.Err() != nil && ctx.Err() == nil {
		return false, false, fmt.Errorf("timeout: %w", attemptCtx.Err())
	}
	return false, false, err
}

// resolverAttemptTimeout derives a per-attempt deadline from ctx, falling
// back to the package default when ctx carries none (direct test callers).
func resolverAttemptTimeout(ctx context.Context) time.Duration {
	if dl, ok := ctx.Deadline(); ok {
		if remaining := time.Until(dl); remaining > 0 {
			return remaining
		}
	}
	return DefaultTimeout
}

// ---------------------------------------------------------------------------
// Framed stream transports: DNS over TCP and DNS over TLS (RFC 7858 share
// TCP's two-byte length framing). One connection per attempt keeps state
// handling trivial and avoids stale-connection pitfalls.

type streamTransport struct {
	kind string // "tcp" or "tls"
	addr string
	conf *tls.Config // nil for plain tcp
}

func (t *streamTransport) describe() string { return t.kind + " " + t.addr }

func (t *streamTransport) lookupNS(ctx context.Context, domain string) (bool, bool, error) {
	id := newQueryID()
	query := buildNSQuery(id, domain)

	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", t.addr)
	if err != nil {
		return false, false, err
	}
	// Abort blocking I/O when the attempt context is cancelled. The conn
	// is always closed below, which also releases this goroutine.
	go func() {
		<-ctx.Done()
		raw.Close()
	}()
	var conn net.Conn = raw
	if t.conf != nil {
		tc := tls.Client(raw, t.conf)
		if err := tc.HandshakeContext(ctx); err != nil {
			raw.Close()
			return false, false, fmt.Errorf("%s handshake: %w", t.kind, err)
		}
		conn = tc
	}
	defer conn.Close()

	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}

	frame := append(make([]byte, 2, 2+len(query)), query...)
	binary.BigEndian.PutUint16(frame, uint16(len(query)))
	if _, err := conn.Write(frame); err != nil {
		return false, false, fmt.Errorf("%s write: %w", t.kind, err)
	}

	msg, err := readFramedMessage(conn)
	if err != nil {
		return false, false, fmt.Errorf("%s read: %w", t.kind, err)
	}
	return parseReply(id, msg)
}

func readFramedMessage(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(hdr[:])
	if int(n) > maxReplyBytes {
		return nil, fmt.Errorf("reply of %d bytes exceeds limit", n)
	}
	msg := make([]byte, n)
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

// ---------------------------------------------------------------------------
// DNS over HTTPS (RFC 8484): the wire-format query travels as the POST body
// with Content-Type application/dns-message.

type dohTransport struct {
	url      string
	insecure bool // test hook: skip TLS verification
	client   *http.Client
}

func (t *dohTransport) describe() string { return "doh " + t.url }

func (t *dohTransport) httpClient() *http.Client {
	if t.client != nil {
		return t.client
	}
	if t.insecure {
		cloned := http.DefaultTransport.(*http.Transport).Clone()
		cloned.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test-only hook
		return &http.Client{Transport: cloned}
	}
	return http.DefaultClient
}

func (t *dohTransport) lookupNS(ctx context.Context, domain string) (bool, bool, error) {
	id := newQueryID()
	query := buildNSQuery(id, domain)

	client := t.httpClient()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url, bytes.NewReader(query))
	if err != nil {
		return false, false, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := client.Do(req)
	if err != nil {
		return false, false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, false, fmt.Errorf("unexpected HTTP status %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxReplyBytes+1))
	if err != nil {
		return false, false, fmt.Errorf("reading response body: %w", err)
	}
	if len(body) > maxReplyBytes {
		return false, false, fmt.Errorf("response body exceeds %d bytes", maxReplyBytes)
	}
	return parseReply(id, body)
}
