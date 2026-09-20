package app

import (
	"os"

	"github.com/mattn/go-isatty"
)

// isTerminal reports whether f is attached to a character device (a
// terminal). Redirected output — pipes, files, CI capture — returns
// false, which disables the bottom-line progress renderer so redirected
// output stays pristine.
func isTerminal(f *os.File) bool {
	return isatty.IsTerminal(f.Fd()) || isatty.IsCygwinTerminal(f.Fd())
}
