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
	return New(Options{
		Server:     srv.Addr(),
		Timeout:    500 * time.Millisecond,
		MaxRetries: 2,
		BaseDelay:  5 * time.Millisecond,
		MaxDelay:   20 * time.Millisecond,
	})
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
	_, err := New(Options{Server: srv.Addr(), Timeout: 5 * time.Second, BaseDelay: time.Hour, MaxRetries: 50}).
		HasNS(ctx, "slow.example")
	if err == nil {
		t.Fatal("want cancellation error")
	}
	if time.Since(start) > time.Second {
		t.Fatalf("cancellation ignored; took %v", time.Since(start))
	}
}
