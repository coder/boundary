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
		// Enable IPv4 packet forwarding so the host can route packets between
		// the jail's veth interface and the outside network. Without this,
		// NAT and forwarding rules would have no effect because the kernel
		// would drop transit packets.
		{
			"enable IP forwarding",
			exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1"),
			[]uintptr{},
		},
		// Apply source NAT (MASQUERADE) for all traffic leaving the jail’s
		// private subnet. This rewrites the source IP of packets originating
		// from 192.168.100.0/24 to the host’s external interface IP. It enables:
		//
		//   - outbound connectivity for jailed processes,
		//   - correct return routing from external endpoints,
		//   - avoidance of static IP assignment for the host interface.
		//
		// MASQUERADE is used instead of SNAT so it works even when the host IP
		// changes dynamically.
		{
			"NAT rules for outgoing traffic (MASQUERADE for return traffic)",
			exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "192.168.100.0/24", "-j", "MASQUERADE"),
			[]uintptr{uintptr(unix.CAP_NET_ADMIN)},
		},
		// Redirect *ALL TCP traffic* coming from the jail’s veth interface
		// to the local HTTP/TLS-intercepting proxy. This causes *every* TCP
		// connection (HTTP, HTTPS, plain TCP protocols) initiated by jailed
		// processes to be transparently intercepted.
		//
		// The HTTP proxy will intelligently handle both HTTP and TLS traffic.
		//
		// PREROUTING is used so redirection happens before routing decisions.
		// REDIRECT rewrites the destination IP to 127.0.0.1 and the destination
		// port to the HTTP proxy's port, forcing traffic through the proxy without
		// requiring any configuration inside the jail.
		{
			"Route ALL TCP traffic to HTTP proxy",
			exec.Command("iptables", "-t", "nat", "-A", "PREROUTING", "-i", l.vethHostName, "-p", "tcp", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", l.httpProxyPort)),
			[]uintptr{uintptr(unix.CAP_NET_ADMIN)},
		},
		// Allow forwarding of non-TCP packets originating from the jail’s subnet.
		// This rule is primarily needed for traffic that is *not* intercepted by
		// the TCP REDIRECT rule — for example:
		//
		//   - DNS queries (UDP/53)
		//   - ICMP (ping, errors)
		//   - Any other UDP or non-TCP protocols
		//
		// Redirected TCP flows never reach the FORWARD chain (they are locally
		// redirected in PREROUTING), so this rule does not apply to TCP traffic.
		{
			"Allow outbound non-TCP traffic from jail subnet",
			exec.Command("iptables", "-A", "FORWARD", "-s", "192.168.100.0/24", "-j", "ACCEPT"),
			[]uintptr{uintptr(unix.CAP_NET_ADMIN)},
		},
		// Allow forwarding of return traffic destined for the jail’s subnet for
		// non-TCP flows. This complements the previous FORWARD rule and ensures
		// that responses to DNS (UDP) or ICMP packets can reach the jail.
		//
		// As with the previous rule, this has no effect on TCP traffic because
		// all TCP connections from the jail are intercepted and redirected to
		// the local proxy before reaching the forwarding path.
		{
			"Allow inbound return traffic to jail subnet (non-TCP)",
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
		//{
		//	"delete veth pair",
		//	exec.Command("ip", "link", "del", l.vethHostName),
		//	[]uintptr{uintptr(unix.CAP_NET_ADMIN)},
		//},
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
			"Remove: NAT rules for outgoing traffic (MASQUERADE for return traffic)",
			exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", "192.168.100.0/24", "-j", "MASQUERADE"),
			[]uintptr{uintptr(unix.CAP_NET_ADMIN)},
		},
		{
			"Remove: Route ALL TCP traffic to HTTP proxy",
			exec.Command("iptables", "-t", "nat", "-D", "PREROUTING", "-i", l.vethHostName, "-p", "tcp", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", l.httpProxyPort)),
			[]uintptr{uintptr(unix.CAP_NET_ADMIN)},
		},
		{
			"Remove: Allow outbound non-TCP traffic from jail subnet",
			exec.Command("iptables", "-D", "FORWARD", "-s", "192.168.100.0/24", "-j", "ACCEPT"),
			[]uintptr{uintptr(unix.CAP_NET_ADMIN)},
		},
		{
			"Remove: Allow inbound return traffic to jail subnet (non-TCP)",
			exec.Command("iptables", "-D", "FORWARD", "-d", "192.168.100.0/24", "-j", "ACCEPT"),
			[]uintptr{uintptr(unix.CAP_NET_ADMIN)},
		},
	})
	if err := runner.runIgnoreErrors(); err != nil {
		return err
	}

	return nil
}
