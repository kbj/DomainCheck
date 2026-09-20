package app

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
	"time"
)

// A nil renderer must render and close as no-ops (non-TTY / tests path).
func TestNilProgressRenderer(t *testing.T) {
	var p *progressRenderer
	p.setTotal(10) // must not panic
	p.render(3)    // must not panic
	p.Close()      // must not panic
	_ = renderBar(1, 0)
}

// renderBar shape: width 24, '=' body, '>' head, spaces to fill.
func TestRenderBarShape(t *testing.T) {
	// Zero progress still shows the '>' head (work in progress).
	if got := renderBar(0, 100); got != ">"+strings.Repeat(" ", 23) {
		t.Fatalf("empty bar wrong: %q", got)
	}
	if got := renderBar(50, 100); !strings.HasPrefix(got, strings.Repeat("=", 11)+">") {
		t.Fatalf("half bar wrong: %q", got)
	}
	if got := renderBar(100, 100); got != strings.Repeat("=", 24) {
		t.Fatalf("full bar wrong: %q", got)
	}
	if got := renderBar(1, 0); got != strings.Repeat(" ", 24) {
		t.Fatalf("zero-total bar wrong: %q", got)
	}
	if got := renderBar(101, 100); len(got) != 24 { // clamped, no overflow
		t.Fatalf("over-checked bar wrong: %q", got)
	}
}

// formatHMS covers the h:mm:ss / m:ss switch.
func TestFormatHMS(t *testing.T) {
	cases := map[time.Duration]string{
		0:                  "0:00",
		59 * time.Second:   "0:59",
		61 * time.Second:   "1:01",
		3600 * time.Second: "1h00:00",
		3661 * time.Second: "1h01:01",
	}
	for d, want := range cases {
		if got := formatHMS(d); got != want {
			t.Fatalf("formatHMS(%v)=%q, want %q", d, got, want)
		}
	}
}

// Non-TTY output must produce a nil renderer so redirected scans stay
// byte-identical to the pre-progressbar behavior.
func TestNewProgressRendererNonTTY(t *testing.T) {
	if newProgressRenderer(&bytes.Buffer{}) != nil {
		t.Fatal("bytes.Buffer must not be treated as a TTY")
	}
}

// The layout contract of a rendered frame: bar, percent, counts, timers.
func TestRenderLayout(t *testing.T) {
	var buf bytes.Buffer
	p := &progressRenderer{w: &buf, isTTY: true, started: time.Now(), total: 4}
	p.render(1)

	re := regexp.MustCompile(`^\r\[=+>[ ]*\] +25% 1/4 \| .+ elapsed \| ETA .+`)
	if !re.MatchString(buf.String()) {
		t.Fatalf("frame layout unexpected: %q", buf.String())
	}

	// A shorter frame must be padded to cover the longer previous one.
	p.render(4)
	last := buf.String()
	if !strings.Contains(last, "100%") {
		t.Fatalf("100%% frame missing: %q", last)
	}
}

// Close erases the line: \r, spaces covering the last frame, \r again.
func TestCloseErasesLine(t *testing.T) {
	var buf bytes.Buffer
	p := &progressRenderer{w: &buf, isTTY: true, started: time.Now(), total: 10}
	p.render(5)
	width := p.lastWidth
	buf.Reset()
	p.Close()
	p.Close() // idempotent
	out := buf.String()
	if !strings.HasPrefix(out, "\r") || !strings.HasSuffix(out, "\r") {
		t.Fatalf("erase must be \\r-prefixed and \\r-terminated: %q", out)
	}
	if !strings.Contains(out, strings.Repeat(" ", width)) {
		t.Fatalf("erase must blank the previous width %d: %q", width, out)
	}
}
