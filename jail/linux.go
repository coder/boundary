//go:build linux

package jail

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"time"
)

// LinuxJail implements Jailer using Linux network namespaces
type LinuxJail struct {
	logger        *slog.Logger
	namespace     string
	vethHost      string // Host-side veth interface name for iptables rules
	commandEnv    []string
	httpProxyPort int
	configDir     string
	caCertPath    string
	homeDir       string
	username      string
	uid           int
	gid           int
}

func NewLinuxJail(config Config) (*LinuxJail, error) {
	return &LinuxJail{
		logger:        config.Logger,
		namespace:     newNamespaceName(),
		httpProxyPort: config.HttpProxyPort,
		configDir:     config.ConfigDir,
		caCertPath:    config.CACertPath,
		homeDir:       config.HomeDir,
		username:      config.Username,
		uid:           config.Uid,
		gid:           config.Gid,
	}, nil
}

// Start creates network namespace and configures iptables rules
func (l *LinuxJail) Start() error {
	l.logger.Debug("Setup called")

	e := getEnvs(l.configDir, l.caCertPath)
	l.commandEnv = mergeEnvs(e, map[string]string{})

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

	// Setup iptables rules on host
	err = l.setupIptables()
	if err != nil {
		return fmt.Errorf("failed to setup iptables: %v", err)
	}

	return nil
}

// Command returns an exec.Cmd configured to run within the network namespace
func (l *LinuxJail) Command(command []string) *exec.Cmd {
	l.logger.Debug("Creating command with namespace", "namespace", l.namespace)

	cmdArgs := []string{"netns", "exec", l.namespace}
	cmdArgs = append(cmdArgs, command...)

	cmd := exec.Command("ip", cmdArgs...)
	cmd.Env = l.commandEnv

	return cmd
}

// Close removes the network namespace and iptables rules
func (l *LinuxJail) Close() error {
	l.logger.Debug("Close called")

	// Clean up iptables rules
	err := l.cleanupIptables()
	if err != nil {
		l.logger.Error("Failed to clean up iptables rules", "error", err)
		// Continue with other cleanup even if this fails
	}

	// Clean up networking
	err = l.cleanupNetworking()
	if err != nil {
		l.logger.Error("Failed to clean up networking", "error", err)
		// Continue with other cleanup even if this fails
	}

	// Clean up namespace-specific DNS config directory
	netnsEtc := fmt.Sprintf("/etc/netns/%s", l.namespace)
	err = os.RemoveAll(netnsEtc)
	if err != nil {
		l.logger.Warn("Failed to remove namespace DNS config", "dir", netnsEtc, "error", err)
		// Continue with other cleanup
	}

	// Remove network namespace
	err = l.removeNamespace()
	if err != nil {
		return fmt.Errorf("failed to remove namespace: %v", err)
	}

	return nil
}

// createNamespace creates a new network namespace
func (l *LinuxJail) createNamespace() error {
	cmd := exec.Command("ip", "netns", "add", l.namespace)
	err := cmd.Run()
	if err != nil {
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

	// Store veth interface name for iptables rules
	l.vethHost = vethHost

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
func (l *LinuxJail) setupDNS() error {
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

// setupIptables configures iptables rules for comprehensive TCP traffic interception
func (l *LinuxJail) setupIptables() error {
	// Enable IP forwarding
	cmd := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1")
	_ = cmd.Run() // Ignore error

	// NAT rules for outgoing traffic (MASQUERADE for return traffic)
	cmd = exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "192.168.100.0/24", "-j", "MASQUERADE")
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to add NAT rule: %v", err)
	}

	// COMPREHENSIVE APPROACH: Route ALL TCP traffic to HTTP proxy
	// The HTTP proxy will intelligently handle both HTTP and TLS traffic
	cmd = exec.Command("iptables", "-t", "nat", "-A", "PREROUTING", "-i", l.vethHost, "-p", "tcp", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", l.httpProxyPort))
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to add comprehensive TCP redirect rule: %v", err)
	}

	// TODO: clean up this rules
	cmd = exec.Command("iptables", "-A", "FORWARD", "-s", "192.168.100.0/24", "-j", "ACCEPT")
	err = cmd.Run()
	if err != nil {
		return err
	}

	cmd = exec.Command("iptables", "-A", "FORWARD", "-d", "192.168.100.0/24", "-j", "ACCEPT")
	err = cmd.Run()
	if err != nil {
		return err
	}

	l.logger.Debug("Comprehensive TCP boundarying enabled", "interface", l.vethHost, "proxy_port", l.httpProxyPort)
	return nil
}

// cleanupIptables removes iptables rules
func (l *LinuxJail) cleanupIptables() error {
	// Remove comprehensive TCP redirect rule
	cmd := exec.Command("iptables", "-t", "nat", "-D", "PREROUTING", "-i", l.vethHost, "-p", "tcp", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", l.httpProxyPort))
	err := cmd.Run()
	if err != nil {
		l.logger.Error("Failed to remove TCP redirect rule", "error", err)
		// Continue with other cleanup even if this fails
	}

	// Remove NAT rule
	cmd = exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", "192.168.100.0/24", "-j", "MASQUERADE")
	err = cmd.Run()
	if err != nil {
		l.logger.Error("Failed to remove NAT rule", "error", err)
		// Continue with other cleanup even if this fails
	}

	return nil
}

// cleanupNetworking removes networking configuration
func (l *LinuxJail) cleanupNetworking() error {
	// Generate unique ID to match veth pair
	uniqueID := fmt.Sprintf("%d", time.Now().UnixNano()%10000000) // 7 digits max
	vethHost := fmt.Sprintf("veth_h_%s", uniqueID)                // veth_h_1234567 = 14 chars

	// Clean up networking
	cleanupCmds := []struct {
		description string
		command     *exec.Cmd
	}{
		{"delete veth pair", exec.Command("ip", "link", "del", vethHost)},
	}

	for _, command := range cleanupCmds {
		if err := command.command.Run(); err != nil {
			return fmt.Errorf("failed to %s: %v", command.description, err)
		}
	}

	return nil
}

// removeNamespace removes the network namespace
func (l *LinuxJail) removeNamespace() error {
	cmd := exec.Command("ip", "netns", "del", l.namespace)
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to remove namespace: %v", err)
	}
	return nil
}
