package jail

import (
	"log/slog"
	"os/exec"
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
