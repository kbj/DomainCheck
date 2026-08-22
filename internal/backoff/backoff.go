// Package backoff provides the shared exponential-backoff delay calculation
// used by the WHOIS and DNS clients.
package backoff

import (
	"math/rand/v2"
	"time"
)

// Delay returns the wait before retry number failure+1 (0-based): base
// shifted left by `failure`, capped at max, with up to 25% random jitter
// added so concurrent clients do not synchronize.
func Delay(base, max time.Duration, failure int) time.Duration {
	d := base
	for i := 0; i < failure && d < max; i++ {
		d *= 2
	}
	if d <= 0 || d > max {
		d = max
	}
	jitter := rand.Int64N(int64(d)/4 + 1)
	return d + time.Duration(jitter)
}
