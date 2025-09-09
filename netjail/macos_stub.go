//go:build !darwin

package netjail

import "log/slog"

// newMacOSNetJail is not available on non-macOS platforms
func newMacOSNetJail(config Config, logger *slog.Logger) (NetJail, error) {
	panic("macOS network jail not available on this platform")
}
