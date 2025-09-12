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
	
	return fmt.Sprintf(`#!/bin/bash
set -e

echo "[jail] Starting rootlesskit-style user space networking with slirp4netns..."

# Check if slirp4netns is available
if ! command -v slirp4netns >/dev/null 2>&1; then
  echo "[jail] Warning: slirp4netns not found, falling back to proxy environment"
  echo "[jail] Install with: sudo apt-get install slirp4netns (or equivalent)"
  
  # Fallback to proxy environment approach
  export HTTP_PROXY="http://127.0.0.1:%d"
  export HTTPS_PROXY="http://127.0.0.1:%d"
  export http_proxy="http://127.0.0.1:%d"
  export https_proxy="http://127.0.0.1:%d"
  echo "[jail] Using proxy environment: HTTP_PROXY=$HTTP_PROXY HTTPS_PROXY=$HTTPS_PROXY"
  exec %s
fi

# Create network namespace with slirp4netns (rootlesskit approach)
echo "[jail] Creating user namespace with slirp4netns networking..."

# Start unshare with network namespace
unshare --user --map-root-user --net --mount --pid --fork /bin/bash -c '

echo "[jail] Inside user namespace, setting up slirp4netns..."

# Start slirp4netns to provide user space networking
# This creates a TAP interface and provides NAT networking without privileges
slirp4netns --configure --mtu=1500 --disable-host-loopback $$ tap0 &
SLIRP_PID=$!
echo "[jail] slirp4netns started with PID: $SLIRP_PID"

# Give slirp4netns time to set up the interface
sleep 1

# Configure the TAP interface
echo "[jail] Configuring network interface..."
ip link set tap0 up 2>/dev/null || echo "[jail] Warning: Could not bring up tap0"
ip addr add 10.0.2.100/24 dev tap0 2>/dev/null || echo "[jail] Warning: Could not configure tap0 IP"
ip route add default via 10.0.2.2 dev tap0 2>/dev/null || echo "[jail] Warning: Could not set default route"

# Set up DNS resolution
echo "[jail] Setting up DNS resolution..."
echo "nameserver 10.0.2.3" > /etc/resolv.conf 2>/dev/null || echo "[jail] Warning: Could not set DNS"
echo "nameserver 8.8.8.8" >> /etc/resolv.conf 2>/dev/null || true

# Set up iptables for traffic interception (if available)
echo "[jail] Setting up iptables traffic redirection..."

# Redirect HTTP traffic to jail proxy
if iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-ports %d 2>/dev/null; then
  echo "[jail] HTTP traffic redirected to port %d"
else
  echo "[jail] Note: iptables redirect not available, using proxy environment fallback"
  export HTTP_PROXY="http://127.0.0.1:%d"
  export http_proxy="http://127.0.0.1:%d"
fi

# Redirect HTTPS traffic to jail proxy
if iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-ports %d 2>/dev/null; then
  echo "[jail] HTTPS traffic redirected to port %d"
else
  echo "[jail] Note: iptables redirect not available, using proxy environment fallback"
  export HTTPS_PROXY="http://127.0.0.1:%d"
  export https_proxy="http://127.0.0.1:%d"
fi

# Show network configuration
echo "[jail] Network status:"
ip addr show 2>/dev/null | grep -E "(inet|tap0|lo)" || echo "[jail] Could not show network status"
echo "[jail] DNS configuration:"
cat /etc/resolv.conf 2>/dev/null || echo "[jail] Could not show DNS config"

echo "[jail] slirp4netns user space network ready, running: %s"

# Execute the command
exec %s

'
`, u.httpProxyPort, u.httpsProxyPort, u.httpProxyPort, u.httpsProxyPort, commandStr, u.httpProxyPort, u.httpProxyPort, u.httpProxyPort, u.httpProxyPort, u.httpsProxyPort, u.httpsProxyPort, u.httpsProxyPort, u.httpsProxyPort, commandStr, commandStr)
}

func (u *UserNamespaceLinux) Close() error {
	u.logger.Info("Closing rootlesskit jail")
	return nil
}