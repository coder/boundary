package jail

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
)

// SimpleJail implements Jailer using HTTP_PROXY environment variables instead
// of network namespaces. This mode doesn't require elevated privileges or
// Linux-specific features, making it portable across platforms.
//
// Note: This mode only intercepts traffic from applications that respect
// HTTP_PROXY/HTTPS_PROXY environment variables. Applications that make direct
// connections will bypass the proxy.
type SimpleJail struct {
	logger        *slog.Logger
	httpProxyPort int
	configDir     string
	caCertPath    string
	commandEnv    []string
}

// NewSimpleJail creates a new SimpleJail that uses environment variables
// for proxy configuration.
func NewSimpleJail(config Config) (*SimpleJail, error) {
	return &SimpleJail{
		logger:        config.Logger,
		httpProxyPort: config.HttpProxyPort,
		configDir:     config.ConfigDir,
		caCertPath:    config.CACertPath,
	}, nil
}

// ConfigureBeforeCommandExecution prepares environment variables for the proxy.
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
	
	s.logger.Debug("Configured simple jail with proxy environment variables",
		"proxy_url", proxyURL)
	
	return nil
}

// Command returns an exec.Cmd configured with proxy environment variables.
func (s *SimpleJail) Command(command []string) *exec.Cmd {
	s.logger.Debug("Creating command with proxy environment", "command", command)
	
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Env = s.commandEnv
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	
	return cmd
}

// ConfigureAfterCommandExecution is a no-op for SimpleJail since there's no
// network namespace to configure.
func (s *SimpleJail) ConfigureAfterCommandExecution(processPID int) error {
	return nil
}

// Close is a no-op for SimpleJail since there are no resources to clean up.
func (s *SimpleJail) Close() error {
	return nil
}
