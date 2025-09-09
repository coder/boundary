//go:build linux

package network

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/coder/jail/environment"
)

const (
	namespacePrefix = "coder_jail"
)

// LinuxJail implements NetJail using Linux network namespaces
type LinuxJail struct {
	config    JailConfig
	namespace string
	logger    *slog.Logger
}

// newLinuxJail creates a new Linux network jail instance
func newLinuxJail(config JailConfig, logger *slog.Logger) (*LinuxJail, error) {
	// Generate unique namespace name
	namespace := fmt.Sprintf("%s_%d", namespacePrefix, time.Now().UnixNano()%10000000)

	return &LinuxJail{
		config:    config,
		namespace: namespace,
		logger:    logger,
	}, nil
}

// Setup creates network namespace and configures iptables rules
func (l *LinuxJail) Setup(httpPort, httpsPort int) error {
	l.logger.Debug("Setup called", "httpPort", httpPort, "httpsPort", httpsPort)
	l.config.HTTPPort = httpPort
	l.config.HTTPSPort = httpsPort

	// Setup DNS configuration BEFORE creating namespace
	// This ensures the namespace-specific resolv.conf is available when namespace is created
	l.logger.Debug("Setting up DNS configuration")
	if err := l.setupDNS(); err != nil {
		return fmt.Errorf("failed to setup DNS: %v", err)
	}
	l.logger.Debug("DNS setup completed")

	// Create network namespace
	l.logger.Debug("Creating network namespace", "namespace", l.namespace)
	if err := l.createNamespace(); err != nil {
		return fmt.Errorf("failed to create namespace: %v", err)
	}
	l.logger.Debug("Network namespace created")

	// Setup network interface in namespace
	l.logger.Debug("Setting up networking")
	if err := l.setupNetworking(); err != nil {
		return fmt.Errorf("failed to setup networking: %v", err)
	}
	l.logger.Debug("Networking setup completed")

	// Setup iptables rules
	l.logger.Debug("Setting up iptables rules")
	if err := l.setupIptables(); err != nil {
		return fmt.Errorf("failed to setup iptables: %v", err)
	}
	l.logger.Debug("Iptables setup completed")

	l.logger.Debug("Setup completed successfully")
	return nil
}

// Execute runs a command within the network namespace
func (l *LinuxJail) Execute(command []string, extraEnv map[string]string) error {
	l.logger.Debug("Execute called", "command", command)
	if len(command) == 0 {
		return fmt.Errorf("no command specified")
	}

	// Create command with ip netns exec
	l.logger.Debug("Creating command with namespace", "namespace", l.namespace)
	cmdArgs := []string{"ip", "netns", "exec", l.namespace}
	cmdArgs = append(cmdArgs, command...)
	l.logger.Debug("Full command args", "args", cmdArgs)

	cmd := exec.Command("ip", cmdArgs[1:]...)

	// Set up environment
	l.logger.Debug("Setting up environment")
	env := os.Environ()

	// Restore original user environment if running under sudo
	restoredUserEnv := environment.RestoreOriginalUserEnvironment(l.logger)
	for key, value := range restoredUserEnv {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}

	// Add extra environment variables (including CA cert if provided)
	for key, value := range extraEnv {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}

	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Drop privileges to original user if running under sudo
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		uid, err := environment.GetEffectiveUID()
		if err != nil {
			l.logger.Warn("Failed to get effective UID, subprocess will run as root", "error", err)
		} else {
			gid, err := environment.GetEffectiveGID()
			if err != nil {
				l.logger.Warn("Failed to get effective GID, subprocess will run as root", "error", err)
			} else {
				cmd.SysProcAttr = &syscall.SysProcAttr{
					Credential: &syscall.Credential{
						Uid: uint32(uid),
						Gid: uint32(gid),
					},
				}
				l.logger.Debug("Dropping privileges to original user", "uid", uid, "gid", gid, "user", sudoUser)
			}
		}
	}

	// Start command
	l.logger.Debug("Starting command", "path", cmd.Path, "args", cmd.Args)
	err := cmd.Start()
	if err != nil {
		return fmt.Errorf("failed to start command: %v", err)
	}
	l.logger.Debug("Command started, waiting for completion")

	// Wait for command to complete
	err = cmd.Wait()
	l.logger.Debug("Command completed", "error", err)
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			if status, ok := exitError.Sys().(syscall.WaitStatus); ok {
				l.logger.Debug("Command exit status", "status", status.ExitStatus())
				os.Exit(status.ExitStatus())
			}
		}
		return fmt.Errorf("command failed: %v", err)
	}

	l.logger.Debug("Command executed successfully")
	return nil
}

// Cleanup removes the network namespace and iptables rules
func (l *LinuxJail) Cleanup() error {
	if l.config.SkipCleanup {
		return nil
	}

	// Remove iptables rules
	if err := l.removeIptables(); err != nil {
		return fmt.Errorf("failed to remove iptables rules: %v", err)
	}

	// Clean up namespace-specific DNS config directory
	netnsEtc := fmt.Sprintf("/etc/netns/%s", l.namespace)
	if _, err := os.Stat(netnsEtc); err == nil {
		if err := os.RemoveAll(netnsEtc); err != nil {
			// Don't fail cleanup for this, just log
			fmt.Printf("Warning: failed to remove DNS config directory %s: %v\n", netnsEtc, err)
		}
	}

	// Remove network namespace
	if err := l.removeNamespace(); err != nil {
		return fmt.Errorf("failed to remove namespace: %v", err)
	}

	return nil
}

// createNamespace creates a new network namespace
func (l *LinuxJail) createNamespace() error {
	cmd := exec.Command("ip", "netns", "add", l.namespace)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create namespace: %v", err)
	}
	return nil
}

// setupNetworking configures networking within the namespace
func (l *LinuxJail) setupNetworking() error {
	// Create veth pair with short names (Linux interface names limited to 15 chars)
	// Generate unique ID to avoid conflicts
	uniqueID := fmt.Sprintf("%d", time.Now().UnixNano()%10000000) // 7 digits max
	vethHost := fmt.Sprintf("veth_h_%s", uniqueID)                // veth_h_1234567 = 14 chars
	vethNetJail := fmt.Sprintf("veth_n_%s", uniqueID)             // veth_n_1234567 = 14 chars

	cmd := exec.Command("ip", "link", "add", vethHost, "type", "veth", "peer", "name", vethNetJail)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create veth pair: %v", err)
	}

	// Move netjail end to namespace
	cmd = exec.Command("ip", "link", "set", vethNetJail, "netns", l.namespace)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to move veth to namespace: %v", err)
	}

	// Configure host side of veth pair
	cmd = exec.Command("ip", "addr", "add", "192.168.100.1/24", "dev", vethHost)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to configure host veth: %v", err)
	}

	cmd = exec.Command("ip", "link", "set", vethHost, "up")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to bring up host veth: %v", err)
	}

	// Configure namespace side of veth pair
	cmd = exec.Command("ip", "netns", "exec", l.namespace, "ip", "addr", "add", "192.168.100.2/24", "dev", vethNetJail)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to configure namespace veth: %v", err)
	}

	cmd = exec.Command("ip", "netns", "exec", l.namespace, "ip", "link", "set", vethNetJail, "up")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to bring up namespace veth: %v", err)
	}

	cmd = exec.Command("ip", "netns", "exec", l.namespace, "ip", "link", "set", "lo", "up")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to bring up loopback: %v", err)
	}

	// Set default route in namespace
	cmd = exec.Command("ip", "netns", "exec", l.namespace, "ip", "route", "add", "default", "via", "192.168.100.1")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set default route: %v", err)
	}

	return nil
}

// setupDNS configures DNS resolution for the namespace
// This ensures reliable DNS resolution by using public DNS servers
// instead of relying on the host's potentially complex DNS configuration
func (l *LinuxJail) setupDNS() error {
	// Always create namespace-specific resolv.conf with reliable public DNS servers
	// This avoids issues with systemd-resolved, Docker DNS, and other complex setups
	netnsEtc := fmt.Sprintf("/etc/netns/%s", l.namespace)
	if err := os.MkdirAll(netnsEtc, 0755); err != nil {
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
	if err := os.WriteFile(resolvConfPath, []byte(dnsConfig), 0644); err != nil {
		return fmt.Errorf("failed to write namespace-specific resolv.conf: %v", err)
	}

	l.logger.Debug("DNS setup completed")
	return nil
}

// setupIptables configures iptables rules for traffic redirection
func (l *LinuxJail) setupIptables() error {
	// Enable IP forwarding
	cmd := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1")
	cmd.Run() // Ignore error

	// NAT rules for outgoing traffic
	cmd = exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "192.168.100.0/24", "-j", "MASQUERADE")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add NAT rule: %v", err)
	}

	// Redirect HTTP traffic to proxy
	cmd = exec.Command("ip", "netns", "exec", l.namespace, "iptables", "-t", "nat", "-A", "OUTPUT",
		"-p", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", fmt.Sprintf("192.168.100.1:%d", l.config.HTTPPort))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add HTTP redirect rule: %v", err)
	}

	// Redirect HTTPS traffic to proxy
	cmd = exec.Command("ip", "netns", "exec", l.namespace, "iptables", "-t", "nat", "-A", "OUTPUT",
		"-p", "tcp", "--dport", "443", "-j", "DNAT", "--to-destination", fmt.Sprintf("192.168.100.1:%d", l.config.HTTPSPort))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add HTTPS redirect rule: %v", err)
	}

	return nil
}

// removeIptables removes iptables rules
func (l *LinuxJail) removeIptables() error {
	// Remove NAT rule
	cmd := exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", "192.168.100.0/24", "-j", "MASQUERADE")
	cmd.Run() // Ignore errors during cleanup

	return nil
}

// removeNamespace removes the network namespace
func (l *LinuxJail) removeNamespace() error {
	cmd := exec.Command("ip", "netns", "del", l.namespace)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to remove namespace: %v", err)
	}
	return nil
}
