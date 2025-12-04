//go:build linux

package jail

import (
	"fmt"
	"os/exec"
	"time"

	"golang.org/x/sys/unix"
)

// configureHostNetworkBeforeCmdExec prepares host-side networking before the target
// process is started. At this point the target process is not running, so its PID and network
// namespace ID are not yet known.
func (l *LinuxJail) configureHostNetworkBeforeCmdExec() error {
	// Create veth pair with short names (Linux interface names limited to 15 chars)
	// Generate unique ID to avoid conflicts
	uniqueID := fmt.Sprintf("%d", time.Now().UnixNano()%10000000) // 7 digits max
	vethHostName := fmt.Sprintf("veth_h_%s", uniqueID)            // veth_h_1234567 = 14 chars
	vethJailName := fmt.Sprintf("veth_n_%s", uniqueID)            // veth_n_1234567 = 14 chars

	// Store veth interface name for iptables rules
	l.vethHostName = vethHostName
	l.vethJailName = vethJailName

	runner := newCommandRunner([]*command{
		{
			"create veth pair",
			exec.Command("ip", "link", "add", vethHostName, "type", "veth", "peer", "name", vethJailName),
			[]uintptr{uintptr(unix.CAP_NET_ADMIN)},
		},
		{
			"configure host veth",
			exec.Command("ip", "addr", "add", "192.168.100.1/24", "dev", vethHostName),
			[]uintptr{uintptr(unix.CAP_NET_ADMIN)},
		},
		{
			"bring up host veth",
			exec.Command("ip", "link", "set", vethHostName, "up"),
			[]uintptr{uintptr(unix.CAP_NET_ADMIN)},
		},
	})
	if err := runner.run(); err != nil {
		return err
	}

	return nil
}

// configureHostNetworkAfterCmdExec finalizes host-side networking after the target
// process has started. It moves the jail-side veth into the target process's network
// namespace using the provided PID. This requires the process to be running so
// its PID (and thus its netns) are available.
func (l *LinuxJail) configureHostNetworkAfterCmdExec(pidInt int) error {
	PID := fmt.Sprintf("%v", pidInt)

	runner := newCommandRunner([]*command{
		{
			"move veth to namespace",
			exec.Command("ip", "link", "set", l.vethJailName, "netns", PID),
			[]uintptr{uintptr(unix.CAP_NET_ADMIN)},
		},
	})
	if err := runner.run(); err != nil {
		return err
	}

	return nil
}

// setupIptables configures iptables rules for comprehensive TCP traffic interception
func (l *LinuxJail) configureIptables() error {
	runner := newCommandRunner([]*command{
		{
			"enable IP forwarding",
			exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1"),
			[]uintptr{},
		},
		{
			"NAT rules for outgoing traffic (MASQUERADE for return traffic)",
			exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "192.168.100.0/24", "-j", "MASQUERADE"),
			[]uintptr{uintptr(unix.CAP_NET_ADMIN)},
		},
		{
			// COMPREHENSIVE APPROACH: Route ALL TCP traffic to HTTP proxy
			// The HTTP proxy will intelligently handle both HTTP and TLS traffic
			"Route ALL TCP traffic to HTTP proxy",
			exec.Command("iptables", "-t", "nat", "-A", "PREROUTING", "-i", l.vethHostName, "-p", "tcp", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", l.httpProxyPort)),
			[]uintptr{uintptr(unix.CAP_NET_ADMIN)},
		},
		{
			"iptables FORWARD -s",
			exec.Command("iptables", "-A", "FORWARD", "-s", "192.168.100.0/24", "-j", "ACCEPT"),
			[]uintptr{uintptr(unix.CAP_NET_ADMIN)},
		},
		{
			"iptables FORWARD -d",
			exec.Command("iptables", "-A", "FORWARD", "-d", "192.168.100.0/24", "-j", "ACCEPT"),
			[]uintptr{uintptr(unix.CAP_NET_ADMIN)},
		},
	})
	if err := runner.run(); err != nil {
		return err
	}

	l.logger.Debug("Comprehensive TCP boundarying enabled", "interface", l.vethHostName, "proxy_port", l.httpProxyPort)
	return nil
}

// cleanupNetworking removes networking configuration
func (l *LinuxJail) cleanupNetworking() error {
	runner := newCommandRunner([]*command{
		// NOTE: seems that command is unnecessary, because device is automatically deleted when boundary exits
		//	{
		//		"delete veth pair",
		//		exec.Command("ip", "link", "del", l.vethHostName),
		//		[]uintptr{uintptr(unix.CAP_NET_ADMIN)},
		//	},
	})
	if err := runner.runIgnoreErrors(); err != nil {
		return err
	}

	return nil
}

// cleanupIptables removes iptables rules
func (l *LinuxJail) cleanupIptables() error {
	runner := newCommandRunner([]*command{
		{
			"Remove comprehensive TCP redirect rule",
			exec.Command("iptables", "-t", "nat", "-D", "PREROUTING", "-i", l.vethHostName, "-p", "tcp", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", l.httpProxyPort)),
			[]uintptr{uintptr(unix.CAP_NET_ADMIN)},
		},
		{
			"Remove NAT rule",
			exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", "192.168.100.0/24", "-j", "MASQUERADE"),
			[]uintptr{uintptr(unix.CAP_NET_ADMIN)},
		},
		{
			"Remove iptables FORWARD -s",
			exec.Command("iptables", "-D", "FORWARD", "-s", "192.168.100.0/24", "-j", "ACCEPT"),
			[]uintptr{uintptr(unix.CAP_NET_ADMIN)},
		},
		{
			"Remove iptables FORWARD -d",
			exec.Command("iptables", "-D", "FORWARD", "-d", "192.168.100.0/24", "-j", "ACCEPT"),
			[]uintptr{uintptr(unix.CAP_NET_ADMIN)},
		},
	})
	if err := runner.runIgnoreErrors(); err != nil {
		return err
	}

	return nil
}
