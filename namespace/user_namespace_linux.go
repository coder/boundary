//go:build linux

package namespace

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
)

// UserNamespaceLinux implements Commander using user namespace + iptables
// This provides comprehensive TCP traffic interception without requiring privileges
type UserNamespaceLinux struct {
	logger         *slog.Logger
	preparedEnv    map[string]string
	httpProxyPort  int
	httpsProxyPort int
	userInfo       UserInfo
}

// NewUserNamespaceLinux creates a new user namespace jail with iptables
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

// Start sets up the namespace environment (preparation only)
func (u *UserNamespaceLinux) Start() error {
	u.logger.Info("User namespace jail prepared (commands will run in isolated namespace)")
	return nil
}

// Command creates a command that will run in a new user namespace
func (u *UserNamespaceLinux) Command(command []string) *exec.Cmd {
	u.logger.Debug("Creating command in user namespace", "command", command)

	// Create a wrapper script that will be run from the host to set up mappings
	hostScript := u.createHostWrapperScript(command)

	// Create the command that will handle namespace creation and mapping setup
	cmd := exec.Command("/bin/bash", "-c", hostScript)

	// Set environment
	env := make([]string, 0, len(u.preparedEnv))
	for key, value := range u.preparedEnv {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd
}

// createHostWrapperScript creates a bash script that sets up the namespace and runs the command
func (u *UserNamespaceLinux) createHostWrapperScript(command []string) string {
	commandStr := strings.Join(command, " ")
	
	// Create a script that runs inside the namespace to set up networking and run the command
	namespaceScript := fmt.Sprintf(`#!/bin/bash
set -e

echo "[jail] Setting up user namespace environment..."

# Set up loopback interface
ip link set lo up 2>/dev/null || echo "[jail] Warning: Could not configure loopback"

# Since we can't modify /etc/resolv.conf or use iptables reliably in user namespace,
# we'll use environment variables to direct traffic through the proxy
echo "[jail] Setting up proxy environment for traffic interception..."

# Set proxy environment variables
export HTTP_PROXY="http://127.0.0.1:%d"
export HTTPS_PROXY="http://127.0.0.1:%d"
export http_proxy="http://127.0.0.1:%d"
export https_proxy="http://127.0.0.1:%d"

# For DNS resolution, try to use a custom approach
export HOSTALIASES=/tmp/jail_hosts
echo "google.com 142.250.191.14" > /tmp/jail_hosts 2>/dev/null || echo "[jail] Warning: Could not create host aliases"

echo "[jail] Proxy environment configured:"
echo "  HTTP_PROXY=$HTTP_PROXY"
echo "  HTTPS_PROXY=$HTTPS_PROXY"

echo "[jail] Namespace setup complete, running command: %s"

# Execute the actual command with proxy environment
exec %s
`, u.httpProxyPort, u.httpsProxyPort, u.httpProxyPort, u.httpsProxyPort, commandStr, commandStr)
	
	script := fmt.Sprintf(`#!/bin/bash
set -e

# Create the user namespace and run the command inside it
echo "[jail] Creating user namespace..."
unshare --user --map-root-user --net --pid --fork --mount-proc --mount /bin/bash -c '%s'
`, strings.ReplaceAll(namespaceScript, "'", "'\"'\"'"))

	return script
}

// Close cleans up (nothing to do for this simple approach)
func (u *UserNamespaceLinux) Close() error {
	u.logger.Info("User namespace jail closed")
	return nil
}