package jail

import (
	"fmt"
	"log/slog"
	"os/exec"
)

type Unprivileged struct {
	logger        *slog.Logger
	commandEnv    []string
	httpProxyPort int
	configDir     string
	caCertPath    string
	homeDir       string
	username      string
	uid           int
	gid           int
}

func NewUnprivileged(config Config) (*Unprivileged, error) {
	return &Unprivileged{
		logger:        config.Logger,
		httpProxyPort: config.HttpProxyPort,
		configDir:     config.ConfigDir,
		caCertPath:    config.CACertPath,
		homeDir:       config.HomeDir,
		username:      config.Username,
		uid:           config.Uid,
		gid:           config.Gid,
	}, nil
}

func (u *Unprivileged) ConfigureBeforeCommandExecution() error {
	u.logger.Debug("Starting in unprivileged mode")
	e := getEnvs(u.configDir, u.caCertPath)
	p := fmt.Sprintf("http://localhost:%d", u.httpProxyPort)
	u.commandEnv = mergeEnvs(e, map[string]string{
		"HOME":        u.homeDir,
		"USER":        u.username,
		"LOGNAME":     u.username,
		"HTTP_PROXY":  p,
		"HTTPS_PROXY": p,
		"http_proxy":  p,
		"https_proxy": p,
	})
	return nil
}

func (u *Unprivileged) Command(command []string) *exec.Cmd {
	u.logger.Debug("Creating unprivileged command", "command", command)

	cmd := exec.Command(command[0], command[1:]...)
	cmd.Env = u.commandEnv

	return cmd
}

func (u *Unprivileged) Close() error {
	u.logger.Debug("Closing unprivileged jail")
	return nil
}

func (u *Unprivileged) ConfigureAfterCommandExecution(processPID int) error {
	return nil
}
