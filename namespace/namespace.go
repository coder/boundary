package namespace

import (
	"fmt"
	"log/slog"
	"runtime"
	"time"

	"github.com/coder/jail"
)

const (
	namespacePrefix = "coder_jail"
)

// JailConfig holds configuration for network jail
type Config struct {
	HTTPPort  int
	HTTPSPort int
	Env       map[string]string
}

// NewJail creates a new NetJail instance for the current platform
func New(config Config, logger *slog.Logger) (jail.Commander, error) {
	switch runtime.GOOS {
	case "darwin":
		return newMacOSJail(config, logger)
	case "linux":
		return newLinux(config, logger)
	default:
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

func newNamespaceName() string {
	return fmt.Sprintf("%s_%d", namespacePrefix, time.Now().UnixNano()%10000000)
}
