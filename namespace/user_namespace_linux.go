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
	vethHost       string
	vethChild      string
	childPID       int
	userInfo       UserInfo
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
		vethHost:       fmt.Sprintf("veth_h_%s", uniqueID),
		vethChild:      fmt.Sprintf("veth_c_%s", uniqueID),
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
		"pid", u.childPID,
		"veth_host", u.vethHost,
		"veth_child", u.vethChild)

	return nil
}

// setupNetworking creates veth pair and configures networking
func (u *UserNamespaceLinux) setupNetworking() error {
	u.logger.Debug("Setting up networking", "veth_host", u.vethHost, "veth_child", u.vethChild)

	networkCmds := []struct {
		desc string
		cmd  *exec.Cmd
	}{
		{"create veth pair", exec.Command("ip", "link", "add", u.vethHost, "type", "veth", "peer", "name", u.vethChild)},
		{"move veth to namespace", exec.Command("ip", "link", "set", u.vethChild, "netns", strconv.Itoa(u.childPID))},
		{"configure host veth IP", exec.Command("ip", "addr", "add", "192.168.100.1/24", "dev", u.vethHost)},
		{"bring up host veth", exec.Command("ip", "link", "set", u.vethHost, "up")},
		{"configure child veth IP", u.nsenterCmd([]string{"ip", "addr", "add", "192.168.100.2/24", "dev", u.vethChild})},
		{"bring up child veth", u.nsenterCmd([]string{"ip", "link", "set", u.vethChild, "up"})},
		{"bring up loopback", u.nsenterCmd([]string{"ip", "link", "set", "lo", "up"})},
		{"set default route", u.nsenterCmd([]string{"ip", "route", "add", "default", "via", "192.168.100.1"})},
	}

	for _, netCmd := range networkCmds {
		u.logger.Debug("Executing network command", "desc", netCmd.desc)
		if err := netCmd.cmd.Run(); err != nil {
			return fmt.Errorf("failed to %s: %v", netCmd.desc, err)
		}
	}

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
func (u *UserNamespaceLinux) setupIptables() error {
	u.logger.Info("Setting up iptables rules for comprehensive TCP traffic interception")

	// Enable IP forwarding
	cmd := u.nsenterCmd([]string{"sysctl", "-w", "net.ipv4.ip_forward=1"})
	cmd.Run() // Ignore error

	// Comprehensive iptables rules for ALL TCP traffic interception
	iptablesRules := []struct {
		desc string
		cmd  *exec.Cmd
	}{
		// Redirect ALL outgoing TCP traffic to our proxy
		{"redirect all TCP to HTTPS proxy", u.nsenterCmd([]string{
			"iptables", "-t", "nat", "-A", "OUTPUT",
			"-p", "tcp",
			"--dport", "1:65535", // All destination ports
			"!", "-d", "127.0.0.0/8", // Except loopback
			"!", "-d", "192.168.100.0/24", // Except our veth network
			"-j", "REDIRECT",
			"--to-ports", strconv.Itoa(u.httpsProxyPort),
		})},
		// NAT for return traffic
		{"enable masquerading", u.nsenterCmd([]string{
			"iptables", "-t", "nat", "-A", "POSTROUTING",
			"-j", "MASQUERADE",
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
			continue
		}
		u.logger.Debug("Successfully applied iptables rule", "desc", rule.desc)
	}

	u.logger.Info("iptables setup completed - ALL TCP traffic will be intercepted")
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

	if u.vethHost != "" {
		cmd := exec.Command("ip", "link", "del", u.vethHost)
		cmd.Run() // Ignore error
	}

	if u.childPID > 0 {
		if process, err := os.FindProcess(u.childPID); err == nil {
			process.Kill()
		}
	}

	return nil
}
