//go:build !linux

package network

import (
	"fmt"
	"log/slog"
)

// newLinuxJail is not available on non-Linux platforms
func newLinuxJail(_ JailConfig, _ *slog.Logger) (Jail, error) {
	return nil, fmt.Errorf("linux network jail not supported on this platform")
}
