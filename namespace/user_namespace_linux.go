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

# Create network namespace with slirp4netns (rootlesskit approach)
echo "[jail] Creating user namespace with slirp4netns networking..."

# Start the parent process that will coordinate slirp4netns
(
  # Create the user namespace with network isolation
  unshare --user --map-root-user --net --mount --pid --fork /bin/bash -c '
  
  # We are now inside the user namespace
  CHILD_PID=$$
  echo "[jail] Inside user namespace with PID: $CHILD_PID"
  
  # Set up basic loopback
  ip link set lo up
  
  # Tell parent our PID so it can start slirp4netns
  echo "[jail] Notifying parent of child PID: $CHILD_PID"
  
  # Wait for slirp4netns to be set up by parent (outside the namespace)
  echo "[jail] Waiting for slirp4netns setup..."
  sleep 3
  
  # Check if tap0 interface was created by slirp4netns
  if ip link show tap0 >/dev/null 2>&1; then
    echo "[jail] Found tap0 interface, configuring..."
    ip link set tap0 up || echo "[jail] Warning: Could not bring up tap0"
    # slirp4netns should have already configured the IP
  else
    echo "[jail] Warning: No tap0 interface found - slirp4netns may have failed"
  fi
  
  # Set up simple proxy forwarders inside the namespace
  echo "[jail] Setting up proxy forwarders to host..."
  
  # Start HTTP proxy forwarder (127.0.0.1:8080 -> 10.0.2.2:8080)
  if command -v socat >/dev/null 2>&1; then
    echo "[jail] Starting HTTP proxy forwarder with socat..."
    socat TCP-LISTEN:8080,fork TCP:10.0.2.2:%d &
    HTTP_FORWARDER_PID=$!
    echo "[jail] HTTP forwarder started with PID: $HTTP_FORWARDER_PID"
    
    echo "[jail] Starting HTTPS proxy forwarder with socat..."
    socat TCP-LISTEN:8443,fork TCP:10.0.2.2:%d &
    HTTPS_FORWARDER_PID=$!
    echo "[jail] HTTPS forwarder started with PID: $HTTPS_FORWARDER_PID"
    
    # Set proxy environment variables to use localhost
    export HTTP_PROXY="http://127.0.0.1:8080"
    export HTTPS_PROXY="http://127.0.0.1:8443"
    export http_proxy="http://127.0.0.1:8080"
    export https_proxy="http://127.0.0.1:8443"
    
    echo "[jail] Proxy forwarders configured (socat)"
  elif command -v nc >/dev/null 2>&1; then
    echo "[jail] Starting simple relay with netcat..."
    # Create simple relay scripts that should work with most netcat versions
    (
      while true; do
        nc -l -p 8080 -e /bin/sh -c "exec nc 10.0.2.2 %d" 2>/dev/null || \
        nc -l 8080 -c "nc 10.0.2.2 %d" 2>/dev/null || \
        break
      done
    ) &
    HTTP_FORWARDER_PID=$!
    
    (
      while true; do
        nc -l -p 8443 -e /bin/sh -c "exec nc 10.0.2.2 %d" 2>/dev/null || \
        nc -l 8443 -c "nc 10.0.2.2 %d" 2>/dev/null || \
        break
      done
    ) &
    HTTPS_FORWARDER_PID=$!
    
    export HTTP_PROXY="http://127.0.0.1:8080"
    export HTTPS_PROXY="http://127.0.0.1:8443"
    export http_proxy="http://127.0.0.1:8080"
    export https_proxy="http://127.0.0.1:8443"
    
    echo "[jail] Proxy forwarders configured (netcat)"
  else
    echo "[jail] Neither socat nor netcat available, using direct connection to gateway"
    export HTTP_PROXY="http://10.0.2.2:%d"
    export HTTPS_PROXY="http://10.0.2.2:%d"
    export http_proxy="http://10.0.2.2:%d"
    export https_proxy="http://10.0.2.2:%d"
  fi
  
  # Show current network status
  echo "[jail] Network configuration:"
  ip addr show 2>/dev/null | grep -E "(inet|tap0|lo)" || echo "[jail] Could not show interfaces"
  echo "[jail] Proxy environment: HTTP_PROXY=$HTTP_PROXY HTTPS_PROXY=$HTTPS_PROXY"
  
  echo "[jail] User space network ready, running: %s"
  
  # Execute the command with proxy environment set
  %s
  COMMAND_EXIT=$?
  
  # Clean up forwarders
  if [ ! -z "$HTTP_FORWARDER_PID" ]; then
    kill $HTTP_FORWARDER_PID 2>/dev/null || true
  fi
  if [ ! -z "$HTTPS_FORWARDER_PID" ]; then
    kill $HTTPS_FORWARDER_PID 2>/dev/null || true
  fi
  
  exit $COMMAND_EXIT
  
  ' &
  
  # Get the PID of the namespace process
  NAMESPACE_PID=$!
  echo "[jail] Namespace process started with PID: $NAMESPACE_PID"
  
  # Give the namespace a moment to start
  sleep 0.5
  
  # Start slirp4netns to provide networking to the namespace
  echo "[jail] Starting slirp4netns for PID $NAMESPACE_PID..."
  slirp4netns --configure --mtu=1500 --disable-host-loopback $NAMESPACE_PID tap0 &
  SLIRP_PID=$!
  echo "[jail] slirp4netns started with PID: $SLIRP_PID"
  
  # Wait for the namespace process to complete
  wait $NAMESPACE_PID
  NAMESPACE_EXIT=$?
  
  # Clean up slirp4netns
  if kill $SLIRP_PID 2>/dev/null; then
    echo "[jail] Cleaned up slirp4netns process"
  fi
  
  exit $NAMESPACE_EXIT
)
`, u.httpProxyPort, u.httpsProxyPort, u.httpProxyPort, u.httpsProxyPort, u.httpProxyPort, u.httpsProxyPort, commandStr, commandStr)
}

func (u *UserNamespaceLinux) Close() error {
	u.logger.Info("Closing rootlesskit jail")
	return nil
}