package network

import (
	"fmt"
	"log/slog"
	"runtime"
)

// Jail represents a network isolation mechanism
type Jail interface {
	// Setup configures the network jail for the given proxy ports
	Setup(httpPort, httpsPort int) error

	// Execute runs a command within the network jail with additional environment variables
	Execute(command []string, extraEnv map[string]string) error

	// Cleanup removes network jail resources
	Cleanup() error
}

// JailConfig holds configuration for network jail
type JailConfig struct {
	HTTPPort    int
	HTTPSPort   int
	NetJailName string
	SkipCleanup bool
}

// NewJail creates a new NetJail instance for the current platform
func NewJail(config JailConfig, logger *slog.Logger) (Jail, error) {
	switch runtime.GOOS {
	case "darwin":
		return newMacOSJail(config, logger)
	case "linux":
		return newLinuxJail(config, logger)
	default:
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}
