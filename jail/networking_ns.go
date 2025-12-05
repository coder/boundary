package jail

import (
	"os/exec"

	"golang.org/x/sys/unix"
)

// SetupChildNetworking configures networking within the target process's network
// namespace. This runs inside the child process after it has been
// created and moved to its own network namespace.
func SetupChildNetworking(vethNetJail string) error {
	runner := newCommandRunner([]*command{
		{
			"configure namespace veth",
			exec.Command("ip", "addr", "add", "192.168.100.2/24", "dev", vethNetJail),
			[]uintptr{uintptr(unix.CAP_NET_ADMIN)},
		},
		{
			"bring up namespace veth",
			exec.Command("ip", "link", "set", vethNetJail, "up"),
			[]uintptr{uintptr(unix.CAP_NET_ADMIN)},
		},
		{
			"bring up loopback",
			exec.Command("ip", "link", "set", "lo", "up"),
			[]uintptr{uintptr(unix.CAP_NET_ADMIN)},
		},
		{
			"set default route in namespace",
			exec.Command("ip", "route", "add", "default", "via", "192.168.100.1"),
			[]uintptr{uintptr(unix.CAP_NET_ADMIN)},
		},
	})
	if err := runner.run(); err != nil {
		return err
	}

	return nil
}

func ConfigureDNSForLocalStubResolver() error {
	runner := newCommandRunner([]*command{
		// Redirect all DNS queries inside the namespace to the host DNS listener.
		// Needed because systemd-resolved listens on a host-side IP, not inside the namespace.
		{
			"Redirect DNS queries (DNAT 53 → host DNS)",
			exec.Command("iptables", "-t", "nat", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "DNAT", "--to-destination", "192.168.100.1:53"),
			[]uintptr{uintptr(unix.CAP_NET_ADMIN)},
		},
		// Rewrite the SOURCE IP of redirected DNS packets.
		// Required because DNS queries originating as 127.0.0.1 inside the namespace
		// must not leave the namespace with a loopback source (kernel drops them).
		// SNAT ensures packets arrive at systemd-resolved with a valid, routable source.
		{
			"Fix DNS source IP (SNAT 127.0.0.x → 192.168.100.2)",
			exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-p", "udp", "--dport", "53", "-d", "192.168.100.1", "-j", "SNAT", "--to-source", "192.168.100.2"),
			[]uintptr{uintptr(unix.CAP_NET_ADMIN)},
		},
		// Allow packets destined for 127.0.0.0/8 to go through routing and NAT.
		// Without this, DNS queries to 127.0.0.53 never hit iptables OUTPUT
		// and cannot be redirected to the host.
		{
			"Allow loopback-destined traffic to pass through NAT (route_localnet)",
			// TODO(yevhenii): consider replacing with specific interfaces instead of all
			exec.Command("sysctl", "-w", "net.ipv4.conf.all.route_localnet=1"),
			[]uintptr{uintptr(unix.CAP_NET_ADMIN)},
		},
	})
	if err := runner.run(); err != nil {
		return err
	}

	return nil
}
