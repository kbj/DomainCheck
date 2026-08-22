package whois

import (
	"bufio"
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/uselibrary/DomainCheck/internal/backoff"
	"time"
)

// startServer runs a minimal fake WHOIS server. respond receives the queried
// domain and returns the raw response bytes.
func startServer(t *testing.T, respond func(domain string) string) (addr string, hits *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	hits = &atomic.Int64{}
	done := make(chan struct{})
	t.Cleanup(func() {
		close(done)
		ln.Close()
	})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
					continue
				}
			}
			hits.Add(1)
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				line, err := bufio.NewReader(c).ReadString('\n')
				if err != nil {
					return
				}
				domain := strings.TrimSpace(line)
				if out := respond(domain); out != "" {
					c.Write([]byte(out))
				}
			}(conn)
		}
	}()
	return ln.Addr().String(), hits
}

func TestQuerySuccess(t *testing.T) {
	addr, _ := startServer(t, func(d string) string {
		return d + ": object does not exist\n"
	})
	host, port, _ := net.SplitHostPort(addr)
	portNum := 0
	for _, c := range port {
		portNum = portNum*10 + int(c-'0')
	}
	c := NewClient(Options{Port: portNum})
	resp, err := c.Query(context.Background(), "abc.xyz", host)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(resp, "abc.xyz") {
		t.Fatalf("response missing domain: %q", resp)
	}
}

func TestQueryRetriesUntilSuccess(t *testing.T) {
	var fails atomic.Int64
	addr, hits := startServer(t, func(d string) string {
		if fails.Add(1) <= 2 { // drop the first two connections
			return "" // close without response -> read error / empty
		}
		return d + ": no match\n"
	})
	host, port, _ := net.SplitHostPort(addr)
	pn := atoi(port)

	c := NewClient(Options{
		Port:       pn,
		BaseDelay:  10 * time.Millisecond,
		MaxDelay:   50 * time.Millisecond,
		MaxRetries: 3,
	})
	resp, err := c.Query(context.Background(), "retry.me", host)
	if err != nil {
		t.Fatalf("expected eventual success, got %v", err)
	}
	if !strings.Contains(resp, "no match") {
		t.Fatalf("bad response %q", resp)
	}
	if got := hits.Load(); got < 3 {
		t.Fatalf("expected >=3 attempts, got %d", got)
	}
}

func TestQueryExhaustsRetries(t *testing.T) {
	addr, hits := startServer(t, func(d string) string {
		time.Sleep(50 * time.Millisecond) // force client timeout every attempt
		return d + ": late\n"
	})
	host, port, _ := net.SplitHostPort(addr)
	pn := atoi(port)

	c := NewClient(Options{
		Port:       pn,
		Timeout:    20 * time.Millisecond,
		BaseDelay:  5 * time.Millisecond,
		MaxDelay:   20 * time.Millisecond,
		MaxRetries: 2,
	})
	_, err := c.Query(context.Background(), "slow.example", host)
	if err == nil {
		t.Fatal("expected error after exhausting retries")
	}
	if got := hits.Load(); got != 3 { // initial + 2 retries
		t.Fatalf("expected exactly 3 attempts, got %d", got)
	}
	if !strings.Contains(err.Error(), "3 attempt(s)") {
		t.Fatalf("error should mention total attempts: %v", err)
	}
}

func TestQueryStopsOnCancelledContext(t *testing.T) {
	addr, _ := startServer(t, func(string) string { time.Sleep(time.Second); return "late" })
	host, port, _ := net.SplitHostPort(addr)
	pn := atoi(port)

	ctx, cancel := context.WithCancel(context.Background())
	c := NewClient(Options{Port: pn, Timeout: 5 * time.Second, BaseDelay: time.Hour, MaxRetries: 100})
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	_, err := c.Query(ctx, "x.y", host)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("cancellation ignored, took %v", elapsed)
	}
}

func TestBackoffGrows(t *testing.T) {
	base, max := 100*time.Millisecond, 800*time.Millisecond
	var prev time.Duration
	for fail := 0; fail < 6; fail++ {
		d := backoff.Delay(base, max, fail)
		wantCap := base << fail
		if wantCap > max {
			wantCap = max
		}
		if d < wantCap || d > wantCap+(wantCap/4)+1 {
			t.Fatalf("fail=%d: delay %s outside [%s, %s]", fail, d, wantCap, wantCap+(wantCap/4))
		}
		prev = d
		_ = prev
	}
	// far beyond the cap it must stay at max (+ jitter <= max/4)
	if d := backoff.Delay(base, max, 30); d > max+max/4+1 {
		t.Fatalf("backoff not capped: %s", d)
	}
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}
