package dns

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uselibrary/DomainCheck/internal/dns/dnstest"
)

func newChecker(t *testing.T, srv *dnstest.Server) *Checker {
	t.Helper()
	c, err := New(Options{
		Servers:    []string{srv.Addr()},
		Timeout:    500 * time.Millisecond,
		MaxRetries: 2,
		BaseDelay:  5 * time.Millisecond,
		MaxDelay:   20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestHasNSPresent(t *testing.T) {
	srv := dnstest.Start(t)
	srv.SetBehavior(func(d string) dnstest.Response {
		return dnstest.Response{NSNames: []string{"ns1." + d}}
	})
	has, err := newChecker(t, srv).HasNS(context.Background(), "registered.example")
	if err != nil || !has {
		t.Fatalf("want (true,nil), got (%v,%v)", has, err)
	}
}

func TestNoRecordsMeansFalse(t *testing.T) {
	srv := dnstest.Start(t)
	srv.SetBehavior(func(d string) dnstest.Response {
		return dnstest.Response{} // NOERROR, no answers
	})
	has, err := newChecker(t, srv).HasNS(context.Background(), "bare.example")
	if err != nil || has {
		t.Fatalf("want (false,nil), got (%v,%v)", has, err)
	}
}

func TestNXDomainMeansFalse(t *testing.T) {
	srv := dnstest.Start(t)
	srv.SetBehavior(func(d string) dnstest.Response {
		return dnstest.Response{RCode: 3} // NXDOMAIN
	})
	has, err := newChecker(t, srv).HasNS(context.Background(), "missing.example")
	if err != nil || has {
		t.Fatalf("NXDOMAIN should be (false,nil), got (%v,%v)", has, err)
	}
}

func TestServfailRetriesThenGivesUp(t *testing.T) {
	srv := dnstest.Start(t)
	var hits atomic.Int64
	srv.SetBehavior(func(d string) dnstest.Response {
		hits.Add(1)
		return dnstest.Response{RCode: 2} // SERVFAIL: transient-looking
	})
	has, err := newChecker(t, srv).HasNS(context.Background(), "broken.example")
	if err == nil || has {
		t.Fatalf("want error, got (%v,%v)", has, err)
	}
	if !strings.Contains(err.Error(), "3 attempt(s)") {
		t.Fatalf("error should mention attempts: %v", err)
	}
	// Go's resolver retransmits internally, so one logical attempt can hit
	// the server several times; just require at least our attempt budget.
	if got := hits.Load(); got < 3 {
		t.Fatalf("expected >=3 server hits, got %d", got)
	}
}

func TestServfailRecoversOnRetry(t *testing.T) {
	srv := dnstest.Start(t)
	var n atomic.Int64
	srv.SetBehavior(func(d string) dnstest.Response {
		if n.Add(1) < 3 {
			return dnstest.Response{RCode: 2}
		}
		return dnstest.Response{NSNames: []string{"ns." + d}}
	})
	has, err := newChecker(t, srv).HasNS(context.Background(), "flaky.example")
	if err != nil || !has {
		t.Fatalf("want eventual success, got (%v,%v)", has, err)
	}
}

func TestContextCancellationAborts(t *testing.T) {
	srv := dnstest.Start(t)
	srv.SetBehavior(func(d string) dnstest.Response {
		time.Sleep(time.Second)
		return dnstest.Response{RCode: 2}
	})
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(80 * time.Millisecond); cancel() }()
	start := time.Now()
	c, err := New(Options{Servers: []string{srv.Addr()}, Timeout: 5 * time.Second, BaseDelay: time.Hour, MaxRetries: 50})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.HasNS(ctx, "slow.example")
	if err == nil {
		t.Fatal("want cancellation error")
	}
	if time.Since(start) > time.Second {
		t.Fatalf("cancellation ignored; took %v", time.Since(start))
	}
}

func TestInvalidServerSpecFailsFast(t *testing.T) {
	for _, bad := range []string{"", "ftp://example.com", "https://"} {
		if _, err := New(Options{Servers: []string{bad}}); err == nil {
			t.Errorf("spec %q: want error, got nil", bad)
		}
	}
	// Empty list means system resolver and must be accepted.
	if _, err := New(Options{}); err != nil {
		t.Errorf("empty Servers: unexpected error %v", err)
	}
}

// TestRoundRobinAcrossServers verifies that successive queries rotate over
// every configured resolver and that a dead server in the list is skipped on
// retry instead of poisoning the result.
func TestRoundRobinAcrossServers(t *testing.T) {
	good1 := dnstest.Start(t)
	good1.SetBehavior(func(d string) dnstest.Response {
		return dnstest.Response{NSNames: []string{"ns." + d}}
	})
	good2 := dnstest.Start(t)
	good2.SetBehavior(func(d string) dnstest.Response { return dnstest.Response{RCode: 3} })
	dead := "127.0.0.1:1" // nothing listens here

	c, err := New(Options{
		Servers:    []string{good1.Addr(), dead, good2.Addr()},
		Timeout:    300 * time.Millisecond,
		MaxRetries: 5,
		BaseDelay:  5 * time.Millisecond,
		MaxDelay:   20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Query 1 lands on good1 (cursor starts at the first entry).
	has, err := c.HasNS(context.Background(), "a.example")
	if err != nil || !has {
		t.Fatalf("query 1: want (true,nil), got (%v,%v)", has, err)
	}
	// Query 2 would land on the dead server first; the retry must move to
	// good2 and still return a definitive answer.
	has, err = c.HasNS(context.Background(), "b.example")
	if err != nil || has {
		t.Fatalf("query 2: want (false,nil), got (%v,%v)", has, err)
	}
	if hits := good1.HitCount("a.example"); hits != 1 {
		t.Fatalf("good1 hit count for a.example = %d, want 1", hits)
	}
	if hits := good2.HitCount("b.example"); hits != 1 {
		t.Fatalf("good2 hit count for b.example = %d, want 1", hits)
	}
	if hits := good1.HitCount("b.example"); hits != 0 {
		t.Fatalf("retry should have failed over to good2, not good1 (hits=%d)", hits)
	}
}

// --- DoT end-to-end ---------------------------------------------------------

func TestDotTransportEndToEnd(t *testing.T) {
	srv := dnstest.StartDoT(t)
	srv.SetBehavior(func(d string) dnstest.Response {
		return dnstest.Response{NSNames: []string{"ns1." + d}}
	})
	c, err := New(dotTestOptions(srv.TLSAddr()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	has, err := c.HasNS(context.Background(), "tls-registered.example")
	if err != nil || !has {
		t.Fatalf("DoT: want (true,nil), got (%v,%v)", has, err)
	}
}

func TestDotTransportNXDOMAIN(t *testing.T) {
	srv := dnstest.StartDoT(t)
	srv.SetBehavior(func(d string) dnstest.Response { return dnstest.Response{RCode: 3} })
	c, err := New(dotTestOptions(srv.TLSAddr()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	has, err := c.HasNS(context.Background(), "tls-missing.example")
	if err != nil || has {
		t.Fatalf("DoT NXDOMAIN: want (false,nil), got (%v,%v)", has, err)
	}
}

// dotTestOptions builds checker options for the self-signed test servers;
// certificate verification must be off because they are not trusted roots.
func dotTestOptions(addr string) Options {
	return Options{
		Servers:     []string{"tls://" + addr},
		Timeout:     500 * time.Millisecond,
		MaxRetries:  2,
		BaseDelay:   5 * time.Millisecond,
		MaxDelay:    20 * time.Millisecond,
		insecureTLS: true,
	}
}

// --- DoH end-to-end ---------------------------------------------------------

func TestDoHTransportEndToEnd(t *testing.T) {
	srv := dnstest.StartDoH(t)
	srv.SetBehavior(func(d string) dnstest.Response {
		return dnstest.Response{NSNames: []string{"ns1." + d}}
	})
	c, err := New(Options{
		Servers:    []string{srv.URL()},
		Timeout:    500 * time.Millisecond,
		MaxRetries: 2,
		BaseDelay:  5 * time.Millisecond,
		MaxDelay:   20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	has, err := c.HasNS(context.Background(), "doh-registered.example")
	if err != nil || !has {
		t.Fatalf("DoH: want (true,nil), got (%v,%v)", has, err)
	}
}

func TestDoHServerErrorIsTransient(t *testing.T) {
	srv := dnstest.StartDoH(t)
	srv.SetBehavior(func(d string) dnstest.Response { return dnstest.Response{RCode: 2} })
	c, err := New(Options{
		Servers:    []string{srv.URL()},
		Timeout:    500 * time.Millisecond,
		MaxRetries: 1,
		BaseDelay:  5 * time.Millisecond,
		MaxDelay:   20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.HasNS(context.Background(), "doh-broken.example")
	if err == nil || !strings.Contains(err.Error(), "rcode 2") {
		t.Fatalf("want rcode error, got %v", err)
	}
}

// --- spec parsing ------------------------------------------------------------

func TestParseServerSpecDefaults(t *testing.T) {
	cases := []struct {
		in   string
		want string // describe() of the resulting transport
	}{
		{"1.2.3.4", "udp 1.2.3.4:53"},
		{"udp://example.org", "udp example.org:53"},
		{"tcp://[::1]", "tcp [::1]:53"},
		{"tls://dot.example.com", "tls dot.example.com:853"},
		{"tls://10.0.0.1:553", "tls 10.0.0.1:553"},
	}
	for _, tc := range cases {
		tr, err := parseServerSpec(tc.in, false)
		if err != nil {
			t.Errorf("%q: unexpected error %v", tc.in, err)
			continue
		}
		if got := tr.describe(); got != tc.want {
			t.Errorf("%q: describe() = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParseServerSpecErrors(t *testing.T) {
	for _, bad := range []string{
		"",
		"   ",
		"ftp://example.com",
		"https://",      // no host at all
		"udp://[::1:x]", // broken IPv6 literal
	} {
		if _, err := parseServerSpec(bad, false); err == nil {
			t.Errorf("%q: want error, got nil", bad)
		}
	}
}
