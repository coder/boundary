//go:build linux

package namespace

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
	"time"
)

// Linux implements jail.Commander using Linux network namespaces
type Linux struct {
	config      Config
	namespace   string
	logger      *slog.Logger
	preparedEnv []string
	procAttr    *syscall.SysProcAttr
}

// newLinux creates a new Linux network jail instance
func newLinux(config Config, logger *slog.Logger) (*Linux, error) {
	return &Linux{
		config:    config,
		namespace: newNamespaceName(),
		logger:    logger,
	}, nil
}

// Setup creates network namespace and configures iptables rules
func (l *Linux) Open() error {
	l.logger.Debug("Setup called")

	// Setup DNS configuration BEFORE creating namespace
	// This ensures the namespace-specific resolv.conf is available when namespace is created
	err := l.setupDNS()
	if err != nil {
		return fmt.Errorf("failed to setup DNS: %v", err)
	}

	// Create namespace
	err = l.createNamespace()
	if err != nil {
		return fmt.Errorf("failed to create namespace: %v", err)
	}

	// Setup networking within namespace
	err = l.setupNetworking()
	if err != nil {
		return fmt.Errorf("failed to setup networking: %v", err)
	}

	// Setup iptables rules
	err = l.setupIptables()
	if err != nil {
		return fmt.Errorf("failed to setup iptables: %v", err)
	}

	// Prepare environment once during setup
	l.logger.Debug("Preparing environment")
	env := os.Environ()

	// Add extra environment variables from config
	for key, value := range l.config.Env {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}

	// When running under sudo, restore essential user environment variables
	sudoUser := os.Getenv("SUDO_USER")
	if sudoUser != "" {
		user, err := user.Lookup(sudoUser)
		if err == nil {
			// Set HOME to original user's home directory
			env = append(env, fmt.Sprintf("HOME=%s", user.HomeDir))
			// Set USER to original username
			env = append(env, fmt.Sprintf("USER=%s", sudoUser))
			// Set LOGNAME to original username (some tools check this instead of USER)
			env = append(env, fmt.Sprintf("LOGNAME=%s", sudoUser))
			l.logger.Debug("Restored user environment", "home", user.HomeDir, "user", sudoUser)
		}
	}

	// Store prepared environment for use in Command method
	l.preparedEnv = env

	// Prepare process credentials once during setup
	l.logger.Debug("Preparing process credentials")
	var gid, uid int
	sudoUID := os.Getenv("SUDO_UID")
	if sudoUID != "" {
		uid, err = strconv.Atoi(sudoUID)
		if err != nil {
			l.logger.Warn("Invalid SUDO_UID, subprocess will run as root", "sudo_uid", sudoUID, "error", err)
		}
	}
	sudoGID := os.Getenv("SUDO_GID")
	if sudoGID != "" {
		gid, err = strconv.Atoi(sudoGID)
		if err != nil {
			l.logger.Warn("Invalid SUDO_GID, subprocess will run as root", "sudo_gid", sudoGID, "error", err)
		}
	}
	l.procAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: uint32(uid),
			Gid: uint32(gid),
		},
	}

	l.logger.Debug("Setup completed successfully")
	return nil
}

// Command returns an exec.Cmd configured to run within the network namespace
func (l *Linux) Command(command []string) *exec.Cmd {
	l.logger.Debug("Command called", "command", command)

	// Create command with ip netns exec
	l.logger.Debug("Creating command with namespace", "namespace", l.namespace)
	cmdArgs := []string{"ip", "netns", "exec", l.namespace}
	cmdArgs = append(cmdArgs, command...)
	l.logger.Debug("Full command args", "args", cmdArgs)

	cmd := exec.Command("ip", cmdArgs[1:]...)

	// Use prepared environment from Open method
	cmd.Env = l.preparedEnv
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Use prepared process attributes from Open method
	cmd.SysProcAttr = l.procAttr

	return cmd
}

// Cleanup removes the network namespace and iptables rules
func (l *Linux) Close() error {
	// Remove iptables rules
	err := l.removeIptables()
	if err != nil {
		return fmt.Errorf("failed to remove iptables rules: %v", err)
	}

	// Clean up namespace-specific DNS config directory
	netnsEtc := fmt.Sprintf("/etc/netns/%s", l.namespace)
	if _, err := os.Stat(netnsEtc); err == nil {
		err := os.RemoveAll(netnsEtc)
		if err != nil {
			// Don't fail cleanup for this, just log
			fmt.Printf("Warning: failed to remove DNS config directory %s: %v\n", netnsEtc, err)
		}
	}

	// Remove network namespace
	err = l.removeNamespace()
	if err != nil {
		return fmt.Errorf("failed to remove namespace: %v", err)
	}

	return nil
}

// createNamespace creates a new network namespace
func (l *Linux) createNamespace() error {
	cmd := exec.Command("ip", "netns", "add", l.namespace)
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to create namespace: %v", err)
	}
	return nil
}

// setupNetworking configures networking within the namespace
func (l *Linux) setupNetworking() error {
	// Create veth pair with short names (Linux interface names limited to 15 chars)
	// Generate unique ID to avoid conflicts
	uniqueID := fmt.Sprintf("%d", time.Now().UnixNano()%10000000) // 7 digits max
	vethHost := fmt.Sprintf("veth_h_%s", uniqueID)                // veth_h_1234567 = 14 chars
	vethNetJail := fmt.Sprintf("veth_n_%s", uniqueID)             // veth_n_1234567 = 14 chars

	setupCmds := []struct {
		description string
		command     *exec.Cmd
	}{
		{"create veth pair", exec.Command("ip", "link", "add", vethHost, "type", "veth", "peer", "name", vethNetJail)},
		{"move veth to namespace", exec.Command("ip", "link", "set", vethNetJail, "netns", l.namespace)},
		{"configure host veth", exec.Command("ip", "addr", "add", "192.168.100.1/24", "dev", vethHost)},
		{"bring up host veth", exec.Command("ip", "link", "set", vethHost, "up")},
		{"configure namespace veth", exec.Command("ip", "netns", "exec", l.namespace, "ip", "addr", "add", "192.168.100.2/24", "dev", vethNetJail)},
		{"bring up namespace veth", exec.Command("ip", "netns", "exec", l.namespace, "ip", "link", "set", vethNetJail, "up")},
		{"bring up loopback", exec.Command("ip", "netns", "exec", l.namespace, "ip", "link", "set", "lo", "up")},
		{"set default route in namespace", exec.Command("ip", "netns", "exec", l.namespace, "ip", "route", "add", "default", "via", "192.168.100.1")},
	}

	for _, command := range setupCmds {
		if err := command.command.Run(); err != nil {
			return fmt.Errorf("failed to %s: %v", command.description, err)
		}
	}

	return nil
}

// setupDNS configures DNS resolution for the namespace
// This ensures reliable DNS resolution by using public DNS servers
// instead of relying on the host's potentially complex DNS configuration
func (l *Linux) setupDNS() error {
	// Always create namespace-specific resolv.conf with reliable public DNS servers
	// This avoids issues with systemd-resolved, Docker DNS, and other complex setups
	netnsEtc := fmt.Sprintf("/etc/netns/%s", l.namespace)
	err := os.MkdirAll(netnsEtc, 0755)
	if err != nil {
		return fmt.Errorf("failed to create /etc/netns directory: %v", err)
	}

	// Write custom resolv.conf with multiple reliable public DNS servers
	resolvConfPath := fmt.Sprintf("%s/resolv.conf", netnsEtc)
	dnsConfig := `# Custom DNS for network namespace
nameserver 8.8.8.8
nameserver 8.8.4.4
nameserver 1.1.1.1
nameserver 9.9.9.9
options timeout:2 attempts:2
`
	err = os.WriteFile(resolvConfPath, []byte(dnsConfig), 0644)
	if err != nil {
		return fmt.Errorf("failed to write namespace-specific resolv.conf: %v", err)
	}

	l.logger.Debug("DNS setup completed")
	return nil
}

// setupIptables configures iptables rules for traffic redirection
func (l *Linux) setupIptables() error {
	// Enable IP forwarding
	cmd := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1")
	cmd.Run() // Ignore error

	// NAT rules for outgoing traffic
	cmd = exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "192.168.100.0/24", "-j", "MASQUERADE")
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to add NAT rule: %v", err)
	}

	// Redirect HTTP traffic to proxy
	cmd = exec.Command("ip", "netns", "exec", l.namespace, "iptables", "-t", "nat", "-A", "OUTPUT",
		"-p", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", fmt.Sprintf("192.168.100.1:%d", l.config.HTTPPort))
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to add HTTP redirect rule: %v", err)
	}

	// Redirect HTTPS traffic to proxy
	cmd = exec.Command("ip", "netns", "exec", l.namespace, "iptables", "-t", "nat", "-A", "OUTPUT",
		"-p", "tcp", "--dport", "443", "-j", "DNAT", "--to-destination", fmt.Sprintf("192.168.100.1:%d", l.config.HTTPSPort))
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to add HTTPS redirect rule: %v", err)
	}

	return nil
}

// removeIptables removes iptables rules
func (l *Linux) removeIptables() error {
	// Remove NAT rule
	cmd := exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", "192.168.100.0/24", "-j", "MASQUERADE")
	cmd.Run() // Ignore errors during cleanup

	return nil
}

// removeNamespace removes the network namespace
func (l *Linux) removeNamespace() error {
	cmd := exec.Command("ip", "netns", "del", l.namespace)
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to remove namespace: %v", err)
	}
	return nil
}
