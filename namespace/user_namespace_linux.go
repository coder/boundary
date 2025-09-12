//go:build linux

package namespace

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
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
	uniqueID := fmt.Sprintf("%d", time.Now().UnixNano()%1000000)
	vethHost := fmt.Sprintf("veth_h_%s", uniqueID)
	vethChild := fmt.Sprintf("veth_c_%s", uniqueID)
	
	return fmt.Sprintf(`#!/bin/bash
set -e

echo "[jail] Starting rootlesskit-style user space networking..."

# Create veth pair on host before entering namespace
echo "[jail] Creating veth pair: %s <-> %s"
ip link add %s type veth peer name %s || {
  echo "[jail] Error: Failed to create veth pair. User namespaces may not be properly configured."
  echo "[jail] Try: sudo sysctl -w kernel.unprivileged_userns_clone=1"
  exit 1
}

# Start unshare with the child veth moved into the namespace
(
  # Move child veth into the new namespace
  unshare --user --map-root-user --net --mount --pid --fork /bin/bash -c '
  
  CHILD_PID=$$
  echo "[jail] Inside user namespace (PID: $CHILD_PID), setting up networking..."
  
  # Set up loopback
  ip link set lo up
  
  # Wait for parent to configure host side and move veth to us
  sleep 0.5
  
  # Configure our end of the veth pair
  if ip link show %s >/dev/null 2>&1; then
    echo "[jail] Configuring network interface %s"
    ip addr add 192.168.100.2/24 dev %s
    ip link set %s up
    ip route add default via 192.168.100.1
    echo "[jail] Network interface configured"
  else
    echo "[jail] Warning: Network interface %s not found, using loopback only"
  fi
  
  # Set up DNS resolution
  echo "[jail] Setting up DNS resolution..."
  echo "nameserver 8.8.8.8" > /etc/resolv.conf 2>/dev/null || echo "[jail] Warning: Could not set DNS"
  echo "nameserver 8.8.4.4" >> /etc/resolv.conf 2>/dev/null || true
  
  # Set up iptables for traffic interception
  echo "[jail] Setting up iptables traffic redirection..."
  
  # Redirect HTTP traffic (port 80)
  if iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-ports %d 2>/dev/null; then
    echo "[jail] HTTP traffic redirected to port %d"
  else
    echo "[jail] Warning: HTTP redirect failed - iptables may not be available"
  fi
  
  # Redirect HTTPS traffic (port 443)
  if iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-ports %d 2>/dev/null; then
    echo "[jail] HTTPS traffic redirected to port %d"
  else
    echo "[jail] Warning: HTTPS redirect failed - iptables may not be available"
  fi
  
  # Enable IP forwarding
  sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true
  
  # Show network status
  echo "[jail] Network configuration:"
  ip addr show 2>/dev/null || echo "[jail] Could not show network interfaces"
  echo "[jail] Routing table:"
  ip route show 2>/dev/null || echo "[jail] Could not show routes"
  
  echo "[jail] Network isolation active, running: %s"
  exec %s
  
  ' &
  
  NAMESPACE_PID=$!
  echo "[jail] Namespace started with PID: $NAMESPACE_PID"
  
  # Give namespace time to start
  sleep 0.2
  
  # Configure host side of veth pair
  echo "[jail] Configuring host side networking..."
  ip addr add 192.168.100.1/24 dev %s 2>/dev/null || echo "[jail] Warning: Could not configure host veth IP"
  ip link set %s up 2>/dev/null || echo "[jail] Warning: Could not bring up host veth"
  
  # Move child veth into the namespace
  ip link set %s netns $NAMESPACE_PID 2>/dev/null || echo "[jail] Warning: Could not move veth to namespace"
  
  # Enable IP forwarding on host side
  echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "[jail] Warning: Could not enable IP forwarding on host"
  
  # Wait for the namespace process to complete
  wait $NAMESPACE_PID
  
  # Cleanup veth pair
  ip link del %s 2>/dev/null || echo "[jail] Note: veth cleanup may have failed (normal if namespace cleaned up first)"
)
`, vethHost, vethChild, vethHost, vethChild, vethChild, vethChild, vethChild, vethChild, vethChild, u.httpProxyPort, u.httpProxyPort, u.httpsProxyPort, u.httpsProxyPort, commandStr, commandStr, vethHost, vethHost, vethChild, vethHost)
}

func (u *UserNamespaceLinux) Close() error {
	u.logger.Info("Closing rootlesskit jail")
	return nil
}