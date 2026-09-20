// progressbar draws the bottom-of-terminal progress line for a scan.
//
// Design constraints:
//   - Only active when stdout is a TTY; redirected output (pipes, log
//     files, CI) must stay pristine, so Render becomes a no-op there.
//   - Plain \r (carriage return) overwriting instead of ANSI cursor
//     escape codes: works on every terminal including legacy Windows
//     consoles. The line always ends clean with ANSI clear-to-EOL when
//     available so redraws of shorter text leave no residue; on unknown
//     terminals padding to the previous width keeps the same guarantee.
//   - The renderer is called from a ticker goroutine while the scan
//     runs; Close() erases the line so subsequent output starts at a
//     clean left margin.
package app

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// progressRenderer owns the bottom line of the terminal during a scan.
// A nil *progressRenderer is valid and renders nothing (non-TTY output).
type progressRenderer struct {
	w         io.Writer
	isTTY     bool
	mu        sync.Mutex
	lastWidth int // visible width of the last rendered line
	started   time.Time
	total     int
}

// newProgressRenderer returns a renderer on out. It is nil (renders
// nothing) when out is not a terminal.
func newProgressRenderer(out io.Writer) *progressRenderer {
	if f, ok := out.(*os.File); ok && isTerminal(f) {
		return &progressRenderer{w: out, isTTY: true, started: time.Now()}
	}
	return nil
}

// setTotal records the dictionary size for percent/ETA math.
func (p *progressRenderer) setTotal(total int) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.total = total
	p.mu.Unlock()
}

// render draws the progress line: bar, percentage, checked/total,
// failures, elapsed and ETA. Called repeatedly by a ticker; safe for
// concurrent use.
func (p *progressRenderer) render(checked int) {
	if p == nil || !p.isTTY {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	elapsed := time.Since(p.started).Truncate(time.Second)
	remaining := p.total - checked
	if remaining < 0 {
		remaining = 0
	}

	// ETA from the observed rate, computed on a non-zero rate only.
	eta := "--:--:--"
	if checked > 0 && p.total > 0 {
		perDomain := time.Since(p.started) / time.Duration(checked)
		left := perDomain * time.Duration(remaining)
		eta = formatHMS(left)
	}

	line := fmt.Sprintf("[%s] %3d%% %d/%d | %s elapsed | ETA %s",
		renderBar(checked, p.total), 100*checked/p.total, checked, p.total, formatHMS(elapsed), eta)
	p.write(line)
}

// renderBar builds a 24-cell ASCII bar: '=' done, '>' head, ' ' rest.
func renderBar(checked, total int) string {
	const width = 24
	if total <= 0 {
		return strings.Repeat(" ", width)
	}
	done := width * checked / total
	if done > width {
		done = width
	}
	head := ""
	if done < width && checked < total {
		head = ">"
	}
	filled := done - len(head)
	if filled < 0 {
		filled = 0
	}
	return strings.Repeat("=", filled) + head + strings.Repeat(" ", width-done-len(head))
}

// write emits "\r"+line padded/erased to cover the previous line.
func (p *progressRenderer) write(line string) {
	if len(line) < p.lastWidth {
		line += strings.Repeat(" ", p.lastWidth-len(line))
	}
	fmt.Fprint(p.w, "\r"+line)
	p.lastWidth = len(line)
}

// Close erases the progress line so following output starts clean.
// Idempotent; a nil renderer is a no-op.
func (p *progressRenderer) Close() {
	if p == nil || !p.isTTY {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Fprint(p.w, "\r"+strings.Repeat(" ", p.lastWidth)+"\r")
	p.lastWidth = 0
}

// formatHMS renders a duration as compact h:mm:ss (or m:ss below 1h).
func formatHMS(d time.Duration) string {
	sec := int(d.Seconds())
	if sec < 0 {
		sec = 0
	}
	h, m, s := sec/3600, (sec%3600)/60, sec%60
	if h > 0 {
		return fmt.Sprintf("%dh%02d:%02d", h, m, s)
	}
	return fmt.Sprintf("%d:%02d", m, s)
}
