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

# Start the namespace and get its PID for slirp4netns
(
  # Create user namespace with network isolation
  unshare --user --map-root-user --net --pid --fork bash -c '
    CHILD_PID=$$
    echo "[jail] Inside namespace with PID: $CHILD_PID"
    
    # Set up basic loopback interface
    ip link set lo up
    
    # Wait for slirp4netns to be started by parent
    echo "[jail] Waiting for slirp4netns setup..."
    sleep 2
    
    # Try to set up iptables (may not work due to lock file permissions)
    echo "[jail] Setting up traffic redirection..."
    if iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-ports %d 2>/dev/null; then
      echo "[jail] HTTP traffic redirected"
    else
      echo "[jail] iptables HTTP redirect failed - using proxy environment"
      export HTTP_PROXY="http://10.0.2.2:%d"
      export http_proxy="http://10.0.2.2:%d"
    fi
    
    if iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-ports %d 2>/dev/null; then
      echo "[jail] HTTPS traffic redirected"
    else
      echo "[jail] iptables HTTPS redirect failed - using proxy environment"
      export HTTPS_PROXY="http://10.0.2.2:%d"
      export https_proxy="http://10.0.2.2:%d"
    fi
    
    echo "[jail] Network jail ready"
    echo "[jail] Running: %s"
    
    # Run the command
    %s
    exit $?
    
  ' &
  
  NAMESPACE_PID=$!
  echo "[jail] Namespace started with PID: $NAMESPACE_PID"
  
  # Give namespace time to start
  sleep 0.5
  
  # Start slirp4netns with the correct namespace PID
  echo "[jail] Starting slirp4netns for namespace PID: $NAMESPACE_PID"
  slirp4netns --configure --disable-host-loopback $NAMESPACE_PID tap0 &
  SLIRP_PID=$!
  
  # Wait for the namespace to complete
  wait $NAMESPACE_PID
  RESULT=$?
  
  # Clean up slirp4netns
  kill $SLIRP_PID 2>/dev/null || true
  exit $RESULT
)
`, u.httpProxyPort, u.httpProxyPort, u.httpProxyPort, u.httpsProxyPort, u.httpsProxyPort, u.httpsProxyPort, commandStr, commandStr)
}

func (u *UserNamespaceLinux) Close() error {
	u.logger.Info("Closing rootlesskit jail")
	return nil
}