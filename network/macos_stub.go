//go:build !darwin

package network

import "log/slog"

// newMacOSJail is not available on non-macOS platforms
func newMacOSJail(config JailConfig, logger *slog.Logger) (Jail, error) {
	panic("macOS network jail not available on this platform")
}
