package jail

import (
	"fmt"
	"log/slog"
	"os/exec"
	"runtime"
)

type Jailer interface {
	ConfigureBeforeCommandExecution() error
	Command(command []string) *exec.Cmd
	ConfigureAfterCommandExecution(processPID int) error
	Close() error
}

type Config struct {
	Logger        *slog.Logger
	HttpProxyPort int
	Username      string
	Uid           int
	Gid           int
	HomeDir       string
	ConfigDir     string
	CACertPath    string
}

// DefaultOS returns the appropriate jailer implementation for the current operating system
func DefaultOS(config Config) (Jailer, error) {
	switch runtime.GOOS {
	case "linux":
		return NewLinuxJail(config)
	default:
		return nil, fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}
