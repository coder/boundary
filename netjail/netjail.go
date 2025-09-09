package netjail

import (
	"fmt"
	"log/slog"
	"runtime"
)

// NetJail represents a network isolation mechanism
type NetJail interface {
	// Setup configures the network jail for the given proxy ports
	Setup(httpPort, httpsPort int) error

	// Execute runs a command within the network jail with additional environment variables
	Execute(command []string, extraEnv map[string]string) error

	// Cleanup removes network jail resources
	Cleanup() error
}

// Config holds configuration for network jail
type Config struct {
	HTTPPort     int
	HTTPSPort    int
	NetJailName  string
	SkipCleanup  bool
}

// NewNetJail creates a new NetJail instance for the current platform
func NewNetJail(config Config, logger *slog.Logger) (NetJail, error) {
	switch runtime.GOOS {
	case "darwin":
		return newMacOSNetJail(config, logger)
	case "linux":
		return newLinuxNetJail(config, logger)
	default:
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}