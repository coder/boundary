//go:build !linux

package netjail

import (
	"fmt"
	"log/slog"
)

// newLinuxNetJail is not available on non-Linux platforms
func newLinuxNetJail(config Config, logger *slog.Logger) (NetJail, error) {
	return nil, fmt.Errorf("Linux network jail not supported on this platform")
}
