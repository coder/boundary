//go:build linux

package namespace

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
)

// UserNamespaceLinux implements Commander using simple proxy environment variables
type UserNamespaceLinux struct {
	logger         *slog.Logger
	preparedEnv    map[string]string
	httpProxyPort  int
	httpsProxyPort int
	userInfo       UserInfo
}

// NewUserNamespaceLinux creates a simple unprivileged jail that sets proxy variables
func NewUserNamespaceLinux(config Config) (*UserNamespaceLinux, error) {
	preparedEnv := make(map[string]string)
	for key, value := range config.Env {
		preparedEnv[key] = value
	}

	// Add proxy environment variables
	httpProxy := fmt.Sprintf("http://127.0.0.1:%d", config.HttpProxyPort)
	httpsProxy := fmt.Sprintf("http://127.0.0.1:%d", config.HttpsProxyPort)
	
	// Set both uppercase and lowercase proxy variables for maximum compatibility
	preparedEnv["HTTP_PROXY"] = httpProxy
	preparedEnv["http_proxy"] = httpProxy
	preparedEnv["HTTPS_PROXY"] = httpsProxy
	preparedEnv["https_proxy"] = httpsProxy

	return &UserNamespaceLinux{
		logger:         config.Logger,
		preparedEnv:    preparedEnv,
		httpProxyPort:  config.HttpProxyPort,
		httpsProxyPort: config.HttpsProxyPort,
		userInfo:       config.UserInfo,
	}, nil
}

func (u *UserNamespaceLinux) Start() error {
	u.logger.Info("Unprivileged jail using proxy environment variables")
	return nil
}

func (u *UserNamespaceLinux) Command(command []string) *exec.Cmd {
	u.logger.Debug("Creating command with proxy environment", "command", command)

	cmd := exec.Command(command[0], command[1:]...)

	// Build environment with proxy variables
	env := make([]string, 0, len(u.preparedEnv)+10)
	for key, value := range u.preparedEnv {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}
	for _, envVar := range os.Environ() {
		if parts := strings.SplitN(envVar, "=", 2); len(parts) == 2 {
			key := parts[0]
			if _, exists := u.preparedEnv[key]; !exists {
				env = append(env, envVar)
			}
		}
	}

	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd
}

func (u *UserNamespaceLinux) Close() error {
	u.logger.Info("Closing unprivileged jail")
	return nil
}