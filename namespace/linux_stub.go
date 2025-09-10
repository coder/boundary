//go:build !linux

package namespace

import (
	"fmt"
	"log/slog"

	"github.com/coder/jail"
)

// newLinux is not available on non-Linux platforms
func newLinux(_ Config, _ *slog.Logger) (jail.Commander, error) {
	return nil, fmt.Errorf("linux network jail not supported on this platform")
}
