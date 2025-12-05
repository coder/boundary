//go:build linux

package jail

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
)

// SimpleJail implements Jailer using environment variables for proxy configuration.
// This mode does NOT require any special Linux permissions (no CAP_NET_ADMIN, no sudo).
// Trade-off: processes can bypass the proxy by ignoring HTTP_PROXY/HTTPS_PROXY env vars.
type SimpleJail struct {
	logger        *slog.Logger
	commandEnv    []string
	httpProxyPort int
	configDir     string
	caCertPath    string
}

func NewSimpleJail(config Config) (*SimpleJail, error) {
	return &SimpleJail{
		logger:        config.Logger,
		httpProxyPort: config.HttpProxyPort,
		configDir:     config.ConfigDir,
		caCertPath:    config.CACertPath,
	}, nil
}

// ConfigureBeforeCommandExecution prepares environment variables for proxy configuration.
func (s *SimpleJail) ConfigureBeforeCommandExecution() error {
	s.commandEnv = getEnvs(s.configDir, s.caCertPath)

	// Add proxy environment variables
	proxyURL := fmt.Sprintf("http://127.0.0.1:%d", s.httpProxyPort)
	s.commandEnv = append(s.commandEnv,
		fmt.Sprintf("HTTP_PROXY=%s", proxyURL),
		fmt.Sprintf("HTTPS_PROXY=%s", proxyURL),
		fmt.Sprintf("http_proxy=%s", proxyURL),
		fmt.Sprintf("https_proxy=%s", proxyURL),
	)

	s.logger.Debug("Simple jail configured with proxy environment variables", "proxy_url", proxyURL)
	return nil
}

// Command returns an exec.Cmd configured with proxy environment variables.
func (s *SimpleJail) Command(command []string) *exec.Cmd {
	s.logger.Debug("Creating command with proxy environment (simple mode)")

	cmd := exec.Command(command[0], command[1:]...)
	cmd.Env = s.commandEnv
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin

	return cmd
}

// ConfigureAfterCommandExecution is a no-op in simple mode.
func (s *SimpleJail) ConfigureAfterCommandExecution(pidInt int) error {
	return nil
}

// Close is a no-op in simple mode.
func (s *SimpleJail) Close() error {
	return nil
}
