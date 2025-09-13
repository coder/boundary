package namespace

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
)

type Unprivileged struct {
	logger        *slog.Logger
	commandEnv    []string
	httpProxyPort int
	tlsConfigDir  string
	caCertPath    string
	userInfo      UserInfo
}

func NewUnprivileged(config Config) (*Unprivileged, error) {
	return &Unprivileged{
		logger:        config.Logger,
		httpProxyPort: config.HttpProxyPort,
		tlsConfigDir:  config.TlsConfigDir,
		caCertPath:    config.CACertPath,
		userInfo:      config.UserInfo,
	}, nil
}

func (u *Unprivileged) Start() error {
	u.logger.Debug("Starting in unprivileged mode")
	e := getEnvs(u.tlsConfigDir, u.caCertPath)
	u.commandEnv = mergeEnvs(e, map[string]string{
		"HTTP_PROXY":  fmt.Sprintf("http://127.0.0.1:%d", u.httpProxyPort),
		"HTTPS_PROXY": fmt.Sprintf("http://127.0.0.1:%d", u.httpProxyPort),
		"http_proxy":  fmt.Sprintf("http://127.0.0.1:%d", u.httpProxyPort),
		"https_proxy": fmt.Sprintf("http://127.0.0.1:%d", u.httpProxyPort),
	})
	return nil
}

func (u *Unprivileged) Command(command []string) *exec.Cmd {
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Env = u.commandEnv
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd
}

func (u *Unprivileged) Close() error {
	return nil
}
