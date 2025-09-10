//go:build !darwin

package namespace

import (
	"log/slog"

	"github.com/coder/jail"
)

// newMacOSJail is not available on non-macOS platforms
func newMacOSJail(config Config, logger *slog.Logger) (jail.Commander, error) {
	panic("macOS network jail not available on this platform")
}
