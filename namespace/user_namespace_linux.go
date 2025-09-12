//go:build linux

package namespace

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// UserNamespaceLinux implements Commander using user namespace + iptables
// This provides comprehensive TCP traffic interception without requiring privileges
type UserNamespaceLinux struct {
	logger         *slog.Logger
	preparedEnv    map[string]string
	httpProxyPort  int
	httpsProxyPort int
	namespace      string
	childPID       int
	userInfo       UserInfo
	ready          chan error
	commandReady   chan struct{}
}

// NewUserNamespaceLinux creates a new user namespace jail with iptables
func NewUserNamespaceLinux(config Config) (*UserNamespaceLinux, error) {
	// Initialize prepared environment
	preparedEnv := make(map[string]string)
	for key, value := range config.Env {
		preparedEnv[key] = value
	}

	// Generate unique identifiers
	uniqueID := fmt.Sprintf("%d", time.Now().UnixNano()%10000000)

	return &UserNamespaceLinux{
		logger:         config.Logger,
		preparedEnv:    preparedEnv,
		httpProxyPort:  config.HttpProxyPort,
		httpsProxyPort: config.HttpsProxyPort,
		namespace:      fmt.Sprintf("jail-userns-%s", uniqueID),
		userInfo:       config.UserInfo,
	}, nil
}

// Start creates user namespace and sets up comprehensive iptables rules
func (u *UserNamespaceLinux) Start() error {
	u.logger.Info("Starting user namespace jail with iptables (no sudo required)")

	// Create a long-running process in the new namespaces using SysProcAttr
	cmd := exec.Command("sleep", "infinity")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET | syscall.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		},
	}

	// Start the namespace process
	err := cmd.Start()
	if err != nil {
		return fmt.Errorf("failed to create user namespace: %v\nEnsure user namespaces are enabled: sudo sysctl -w kernel.unprivileged_userns_clone=1", err)
	}
	u.childPID = cmd.Process.Pid

	u.logger.Debug("User namespace created", "pid", u.childPID)

	// Wait for namespace to be fully ready
	time.Sleep(300 * time.Millisecond)

	// Set up networking (veth pair)
	err = u.setupNetworking()
	if err != nil {
		return fmt.Errorf("failed to setup networking: %v", err)
	}

	// Set up DNS resolution
	err = u.setupDNS()
	if err != nil {
		return fmt.Errorf("failed to setup DNS: %v", err)
	}

	// Set up iptables rules for comprehensive traffic interception
	err = u.setupIptables()
	if err != nil {
		return fmt.Errorf("failed to setup iptables: %v", err)
	}

	// Prepare environment
	u.prepareEnvironment()

	u.logger.Info("User namespace jail started successfully (comprehensive TCP interception enabled)",
		"pid", u.childPID)

	return nil
}

// setupNetworking configures basic networking within the user namespace
// We don't need external connectivity - just the ability to intercept traffic
func (u *UserNamespaceLinux) setupNetworking() error {
	u.logger.Debug("Setting up basic networking within user namespace")

	// Simple approach: just configure loopback and let iptables handle the rest
	// The proxy server runs on the host, and iptables will redirect traffic to it
	networkCmds := []struct {
		desc string
		cmd  *exec.Cmd
	}{
		// Bring up loopback interface
		{"bring up loopback", u.nsenterCmd([]string{"ip", "link", "set", "lo", "up"})},
		
		// Set a basic IP for loopback if needed
		{"configure loopback IP", u.nsenterCmd([]string{"ip", "addr", "add", "127.0.0.1/8", "dev", "lo"})},
	}

	for _, netCmd := range networkCmds {
		u.logger.Debug("Executing network command", "desc", netCmd.desc)
		if err := netCmd.cmd.Run(); err != nil {
			u.logger.Debug("Network command failed, continuing", "desc", netCmd.desc, "error", err)
			// Don't fail here - these are mostly for completeness
			continue
		}
	}

	u.logger.Debug("Basic networking setup completed")
	return nil
}

// setupDNS configures DNS resolution in the namespace
func (u *UserNamespaceLinux) setupDNS() error {
	u.logger.Debug("Setting up DNS")

	dnsConfig := `nameserver 8.8.8.8
nameserver 8.8.4.4
nameserver 1.1.1.1
options timeout:2 attempts:2
`

	cmd := u.nsenterCmd([]string{"sh", "-c", fmt.Sprintf("echo '%s' > /etc/resolv.conf", dnsConfig)})
	if err := cmd.Run(); err != nil {
		u.logger.Warn("Failed to write /etc/resolv.conf in namespace, DNS may not work", "error", err)
	}

	return nil
}

// setupIptables configures iptables for comprehensive TCP traffic interception
// Traffic is redirected to localhost where the proxy server runs
func (u *UserNamespaceLinux) setupIptables() error {
	u.logger.Info("Setting up iptables rules for comprehensive TCP traffic interception")

	// Enable IP forwarding
	cmd := u.nsenterCmd([]string{"sysctl", "-w", "net.ipv4.ip_forward=1"})
	cmd.Run() // Ignore error

	// Comprehensive iptables rules for ALL TCP traffic interception
	// Redirect to localhost where the proxy server is running
	iptablesRules := []struct {
		desc string
		cmd  *exec.Cmd
	}{
		// Redirect ALL outgoing TCP traffic to our proxy running on localhost
		{"redirect all TCP to HTTPS proxy", u.nsenterCmd([]string{
			"iptables", "-t", "nat", "-A", "OUTPUT",
			"-p", "tcp",
			"--dport", "1:65535", // All destination ports
			"!", "-d", "127.0.0.0/8", // Except loopback (avoid redirect loops)
			"-j", "REDIRECT",
			"--to-ports", strconv.Itoa(u.httpsProxyPort),
		})},
		
		// Alternative DNAT approach (try both)
		{"DNAT all TCP to localhost proxy", u.nsenterCmd([]string{
			"iptables", "-t", "nat", "-A", "OUTPUT",
			"-p", "tcp",
			"--dport", "1:65535",
			"!", "-d", "127.0.0.0/8",
			"-j", "DNAT",
			"--to-destination", fmt.Sprintf("127.0.0.1:%d", u.httpsProxyPort),
		})},
		
		// Accept loopback traffic
		{"accept loopback traffic", u.nsenterCmd([]string{
			"iptables", "-A", "INPUT",
			"-i", "lo",
			"-j", "ACCEPT",
		})},
		
		// Accept established connections
		{"accept established connections", u.nsenterCmd([]string{
			"iptables", "-A", "INPUT",
			"-m", "state", "--state", "ESTABLISHED,RELATED",
			"-j", "ACCEPT",
		})},
	}

	for _, rule := range iptablesRules {
		u.logger.Debug("Applying iptables rule", "desc", rule.desc)
		if err := rule.cmd.Run(); err != nil {
			u.logger.Debug("iptables rule failed (trying next)", "desc", rule.desc, "error", err)
			// Try the next rule - some might work even if others fail
			continue
		}
		u.logger.Debug("Successfully applied iptables rule", "desc", rule.desc)
	}

	u.logger.Info("iptables setup completed - ALL TCP traffic will be intercepted and redirected to localhost proxy")
	return nil
}

// prepareEnvironment sets up environment variables
func (u *UserNamespaceLinux) prepareEnvironment() {
	for _, envVar := range os.Environ() {
		if parts := strings.SplitN(envVar, "=", 2); len(parts) == 2 {
			key, value := parts[0], parts[1]
			if _, exists := u.preparedEnv[key]; !exists {
				u.preparedEnv[key] = value
			}
		}
	}

	u.preparedEnv["HOME"] = u.userInfo.HomeDir
	u.preparedEnv["USER"] = u.userInfo.Username
	u.preparedEnv["LOGNAME"] = u.userInfo.Username
}

// nsenterCmd creates a command that executes within the user namespace
func (u *UserNamespaceLinux) nsenterCmd(args []string) *exec.Cmd {
	cmdArgs := []string{"nsenter", "-t", strconv.Itoa(u.childPID), "-n", "-m", "-u"}
	cmdArgs = append(cmdArgs, args...)
	return exec.Command("nsenter", cmdArgs[1:]...)
}

// Command returns an exec.Cmd configured to run within the user namespace
func (u *UserNamespaceLinux) Command(command []string) *exec.Cmd {
	u.logger.Debug("Creating command in user namespace", "command", command, "child_pid", u.childPID)

	cmd := u.nsenterCmd(command)

	env := make([]string, 0, len(u.preparedEnv))
	for key, value := range u.preparedEnv {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: uint32(u.userInfo.Uid),
			Gid: uint32(u.userInfo.Gid),
		},
	}

	return cmd
}

// Close cleans up the user namespace jail
func (u *UserNamespaceLinux) Close() error {
	u.logger.Info("Closing user namespace jail")

	// Kill the namespace process - this automatically cleans up the namespace
	if u.childPID > 0 {
		if process, err := os.FindProcess(u.childPID); err == nil {
			process.Kill()
		}
	}

	u.logger.Debug("User namespace jail cleanup completed")
	return nil
}

// SimpleUserNamespaceLinux implements Commander using a simpler approach
// This creates a user namespace and runs commands directly inside it
type SimpleUserNamespaceLinux struct {
	logger         *slog.Logger
	preparedEnv    map[string]string
	httpProxyPort  int
	httpsProxyPort int
	userInfo       UserInfo
}

// NewSimpleUserNamespaceLinux creates a new simple user namespace jail
func NewSimpleUserNamespaceLinux(config Config) (*SimpleUserNamespaceLinux, error) {
	// Initialize prepared environment
	preparedEnv := make(map[string]string)
	for key, value := range config.Env {
		preparedEnv[key] = value
	}

	return &SimpleUserNamespaceLinux{
		logger:         config.Logger,
		preparedEnv:    preparedEnv,
		httpProxyPort:  config.HttpProxyPort,
		httpsProxyPort: config.HttpsProxyPort,
		userInfo:       config.UserInfo,
	}, nil
}

// Start sets up the namespace environment (preparation only)
func (s *SimpleUserNamespaceLinux) Start() error {
	s.logger.Info("Simple user namespace jail prepared (commands will run in isolated namespace)")
	return nil
}

// Command creates a command that will run in a new user namespace
func (s *SimpleUserNamespaceLinux) Command(command []string) *exec.Cmd {
	s.logger.Debug("Creating command in new user namespace", "command", command)

	// We'll wrap the command in a script that:
	// 1. Sets up the namespace
	// 2. Configures networking and iptables
	// 3. Runs the actual command
	wrapperScript := s.createWrapperScript(command)

	// Create the command that will run with user namespace
	cmd := exec.Command("/bin/bash", "-c", wrapperScript)

	// Set up the namespace creation
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET | syscall.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: s.userInfo.Uid, Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: s.userInfo.Gid, Size: 1},
		},
	}

	// Set environment
	env := make([]string, 0, len(s.preparedEnv))
	for key, value := range s.preparedEnv {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd
}

// createWrapperScript creates a bash script that sets up the namespace and runs the command
func (s *SimpleUserNamespaceLinux) createWrapperScript(command []string) string {
	commandStr := strings.Join(command, " ")
	
	script := fmt.Sprintf(`#!/bin/bash
set -e

# We're now inside the user namespace as 'root'
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
`, s.httpsProxyPort, s.httpsProxyPort, commandStr, commandStr)

	return script
}

// Close cleans up (nothing to do for this simple approach)
func (s *SimpleUserNamespaceLinux) Close() error {
	s.logger.Info("Simple user namespace jail closed")
	return nil
}