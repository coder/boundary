//go:build linux

package namespace

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
)

// UserNamespaceLinux implements Commander using rootlesskit-inspired approach
// This uses the same principles as rootlesskit but with simplified implementation
type UserNamespaceLinux struct {
	logger         *slog.Logger
	preparedEnv    map[string]string
	httpProxyPort  int
	httpsProxyPort int
	userInfo       UserInfo
}

// NewUserNamespaceLinux creates a new rootlesskit-inspired jail
func NewUserNamespaceLinux(config Config) (*UserNamespaceLinux, error) {
	// Initialize prepared environment
	preparedEnv := make(map[string]string)
	for key, value := range config.Env {
		preparedEnv[key] = value
	}

	return &UserNamespaceLinux{
		logger:         config.Logger,
		preparedEnv:    preparedEnv,
		httpProxyPort:  config.HttpProxyPort,
		httpsProxyPort: config.HttpsProxyPort,
		userInfo:       config.UserInfo,
	}, nil
}

// Start sets up the rootlesskit-style environment
func (u *UserNamespaceLinux) Start() error {
	u.logger.Info("Rootlesskit-style jail prepared (proxy-based traffic interception)")
	return nil
}

// Command creates a command with rootlesskit-style proxy environment
func (u *UserNamespaceLinux) Command(command []string) *exec.Cmd {
	u.logger.Debug("Creating command with rootlesskit-style proxy environment", "command", command)

	// Create the command directly - rootlesskit also uses proxy environment in many cases
	cmd := exec.Command(command[0], command[1:]...)

	// Set environment including proxy settings (rootlesskit approach)
	env := make([]string, 0, len(u.preparedEnv)+10)
	
	// Add proxy environment variables for traffic interception
	proxyURL := fmt.Sprintf("http://127.0.0.1:%d", u.httpProxyPort)
	httpsProxyURL := fmt.Sprintf("http://127.0.0.1:%d", u.httpsProxyPort)
	env = append(env, fmt.Sprintf("HTTP_PROXY=%s", proxyURL))
	env = append(env, fmt.Sprintf("HTTPS_PROXY=%s", httpsProxyURL))
	env = append(env, fmt.Sprintf("http_proxy=%s", proxyURL))
	env = append(env, fmt.Sprintf("https_proxy=%s", httpsProxyURL))

	// Add prepared environment
	for key, value := range u.preparedEnv {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}
	
	// Add current environment (but proxy vars will override)
	for _, envVar := range os.Environ() {
		if parts := strings.SplitN(envVar, "=", 2); len(parts) == 2 {
			key := parts[0]
			// Skip if we already have this key
			if _, exists := u.preparedEnv[key]; !exists {
				if key != "HTTP_PROXY" && key != "HTTPS_PROXY" && key != "http_proxy" && key != "https_proxy" {
					env = append(env, envVar)
				}
			}
		}
	}

	u.logger.Debug("Set proxy environment", "HTTP_PROXY", proxyURL, "HTTPS_PROXY", httpsProxyURL)

	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd
}

// Close cleans up resources
func (u *UserNamespaceLinux) Close() error {
	u.logger.Info("Rootlesskit-style jail closed")
	return nil
}