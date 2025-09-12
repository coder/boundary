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
  
  # Set up proxy forwarders inside the namespace
  echo "[jail] Setting up proxy forwarders to host..."
  
  # Try to set up proxy forwarders, but be prepared to fall back
  FORWARDERS_WORKING=false
  
  if command -v socat >/dev/null 2>&1; then
    echo "[jail] Starting proxy forwarders with socat..."
    socat TCP-LISTEN:8080,fork TCP:10.0.2.2:%d &
    HTTP_FORWARDER_PID=$!
    socat TCP-LISTEN:8443,fork TCP:10.0.2.2:%d &
    HTTPS_FORWARDER_PID=$!
    
    # Give socat a moment to start
    sleep 0.5
    
    # Test if socat is actually listening
    if netstat -tln 2>/dev/null | grep -q ':8080.*LISTEN' && netstat -tln 2>/dev/null | grep -q ':8443.*LISTEN'; then
      echo "[jail] socat proxy forwarders confirmed listening"
      FORWARDERS_WORKING=true
    else
      echo "[jail] socat proxy forwarders failed to start"
      # Clean up failed socat processes
      [ ! -z "$HTTP_FORWARDER_PID" ] && kill $HTTP_FORWARDER_PID 2>/dev/null || true
      [ ! -z "$HTTPS_FORWARDER_PID" ] && kill $HTTPS_FORWARDER_PID 2>/dev/null || true
    fi
  fi
  
  # If socat didn't work, try a different approach
  if [ "$FORWARDERS_WORKING" = "false" ] && command -v nc >/dev/null 2>&1; then
    echo "[jail] Trying simple netcat relay..."
    
    # Test connectivity to the host proxy first
    if timeout 2 nc -z 10.0.2.2 %d 2>/dev/null; then
      echo "[jail] Host proxy reachable on 10.0.2.2:%d"
      
      # Try a simpler netcat approach
      mkfifo /tmp/http_pipe /tmp/https_pipe 2>/dev/null || true
      nc -l 8080 < /tmp/http_pipe | nc 10.0.2.2 %d > /tmp/http_pipe &
      HTTP_FORWARDER_PID=$!
      nc -l 8443 < /tmp/https_pipe | nc 10.0.2.2 %d > /tmp/https_pipe &
      HTTPS_FORWARDER_PID=$!
      
      sleep 0.5
      if netstat -tln 2>/dev/null | grep -q ':8080.*LISTEN'; then
        echo "[jail] netcat proxy forwarders started"
        FORWARDERS_WORKING=true
      else
        echo "[jail] netcat proxy forwarders failed"
        [ ! -z "$HTTP_FORWARDER_PID" ] && kill $HTTP_FORWARDER_PID 2>/dev/null || true
        [ ! -z "$HTTPS_FORWARDER_PID" ] && kill $HTTPS_FORWARDER_PID 2>/dev/null || true
      fi
    else
      echo "[jail] Cannot reach host proxy at 10.0.2.2:%d"
    fi
  fi
  
  # Set proxy environment variables based on what's working
  if [ "$FORWARDERS_WORKING" = "true" ]; then
    export HTTP_PROXY="http://127.0.0.1:8080"
    export HTTPS_PROXY="http://127.0.0.1:8443"
    export http_proxy="http://127.0.0.1:8080"
    export https_proxy="http://127.0.0.1:8443"
    echo "[jail] Using localhost proxy forwarders"
  else
    export HTTP_PROXY="http://10.0.2.2:%d"
    export HTTPS_PROXY="http://10.0.2.2:%d"
    export http_proxy="http://10.0.2.2:%d"
    export https_proxy="http://10.0.2.2:%d"
    echo "[jail] Using direct gateway connection (forwarders failed)"
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
`, u.httpProxyPort, u.httpsProxyPort, u.httpProxyPort, u.httpProxyPort, u.httpProxyPort, u.httpsProxyPort, u.httpProxyPort, u.httpProxyPort, u.httpsProxyPort, u.httpProxyPort, u.httpsProxyPort, commandStr, commandStr)
}

func (u *UserNamespaceLinux) Close() error {
	u.logger.Info("Closing rootlesskit jail")
	return nil
}