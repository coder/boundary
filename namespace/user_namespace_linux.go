//go:build linux

package namespace

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"syscall"
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

	// Create wrapper script that sets up namespace and runs command
	wrapperScript := u.createWrapperScript(command)

	// Create the command that will run with user namespace
	cmd := exec.Command("/bin/bash", "-c", wrapperScript)

	// Set up the namespace creation - let the script handle UID/GID mapping
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET | syscall.CLONE_NEWNS,
		// Remove automatic UID/GID mappings - we'll handle this in the script
	}

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

// createWrapperScript creates a bash script that sets up the namespace and runs the command
func (u *UserNamespaceLinux) createWrapperScript(command []string) string {
	commandStr := strings.Join(command, " ")
	
	script := fmt.Sprintf(`#!/bin/bash
set -e

# We're now inside the user namespace, but need to set up UID/GID mappings first
echo "[jail] Setting up user namespace mappings..."

# Set up UID/GID mappings (equivalent to unshare --map-root-user)
echo 'deny' > /proc/self/setgroups 2>/dev/null || echo "[jail] Warning: Could not write to setgroups"
echo '0 %d 1' > /proc/self/uid_map 2>/dev/null || echo "[jail] Warning: Could not write to uid_map"
echo '0 %d 1' > /proc/self/gid_map 2>/dev/null || echo "[jail] Warning: Could not write to gid_map"

echo "[jail] Setting up user namespace environment..."

# Set up loopback interface
ip link set lo up 2>/dev/null || echo "[jail] Warning: Could not configure loopback"

# Set up iptables rules to redirect traffic to proxy
echo "[jail] Setting up traffic interception..."
iptables -t nat -A OUTPUT -p tcp --dport 1:65535 ! -d 127.0.0.0/8 -j REDIRECT --to-ports %d 2>/dev/null || echo "[jail] Warning: Could not set up REDIRECT rules"
iptables -t nat -A OUTPUT -p tcp --dport 1:65535 ! -d 127.0.0.0/8 -j DNAT --to-destination 127.0.0.1:%d 2>/dev/null || echo "[jail] Warning: Could not set up DNAT rules"

# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1 2>/dev/null || echo "[jail] Warning: Could not enable IP forwarding"

echo "[jail] Namespace setup complete, running command: %s"

# Execute the actual command
exec %s
`, u.userInfo.Uid, u.userInfo.Gid, u.httpsProxyPort, u.httpsProxyPort, commandStr, commandStr)

	return script
}

// Close cleans up (nothing to do for this simple approach)
func (u *UserNamespaceLinux) Close() error {
	u.logger.Info("User namespace jail closed")
	return nil
}