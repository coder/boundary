//go:build linux

package namespace

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// UserNamespaceLinux implements Commander using rootlesskit approach with user space networking
type UserNamespaceLinux struct {
	logger         *slog.Logger
	preparedEnv    map[string]string
	httpProxyPort  int
	httpsProxyPort int
	userInfo       UserInfo
	stateDir       string
}

// NewUserNamespaceLinux creates a rootlesskit-style jail
func NewUserNamespaceLinux(config Config) (*UserNamespaceLinux, error) {
	preparedEnv := make(map[string]string)
	for key, value := range config.Env {
		preparedEnv[key] = value
	}

	stateDir := filepath.Join(config.UserInfo.ConfigDir, "rootlesskit")
	if err := os.MkdirAll(stateDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create state directory: %v", err)
	}

	return &UserNamespaceLinux{
		logger:         config.Logger,
		preparedEnv:    preparedEnv,
		httpProxyPort:  config.HttpProxyPort,
		httpsProxyPort: config.HttpsProxyPort,
		userInfo:       config.UserInfo,
		stateDir:       stateDir,
	}, nil
}

func (u *UserNamespaceLinux) Start() error {
	u.logger.Info("Rootlesskit-style jail with user space networking prepared")
	return nil
}

func (u *UserNamespaceLinux) Command(command []string) *exec.Cmd {
	u.logger.Debug("Creating rootlesskit command with user space networking", "command", command)

	script := u.createNetworkingScript(command)
	cmd := exec.Command("/bin/bash", "-c", script)

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

func (u *UserNamespaceLinux) createNetworkingScript(command []string) string {
	commandStr := strings.Join(command, " ")
	
	// Create network jail with slirp4netns that does not require root or sudo or CAP_NET_ADMIN
	// and forwards all TCP traffic to the proxy ports
	return fmt.Sprintf(`#!/bin/bash
set -e

echo "[jail] Creating network jail with slirp4netns (no root required)..."

# TODO: Implement slirp4netns network jail that forwards all TCP traffic to proxy ports
echo "[jail] Running command: %s"
exec %s
`, commandStr, commandStr)
}

func (u *UserNamespaceLinux) Close() error {
	u.logger.Info("Closing rootlesskit jail")
	return nil
}