package jail

import (
	"os/exec"

	"golang.org/x/sys/unix"
)

// SetupChildNetworking configures networking within the target process's network
// namespace. This runs inside the child process after it has been
// created and moved to its own network namespace.
func SetupChildNetworking(vethNetJail string) error {
	//showCmd := exec.Command("ip", "link", "show")
	//showCmd.SysProcAttr = &syscall.SysProcAttr{
	//	AmbientCaps: []uintptr{uintptr(unix.CAP_NET_ADMIN)},
	//}
	//output, err := showCmd.CombinedOutput()
	//if err != nil {
	//	fmt.Printf("error (ip link show): %v\n", err)
	//	return err
	//}
	//fmt.Printf("output (ip link show): %s\n", output)

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

func ConfigureDNSInNamespace() error {
	runner := newCommandRunner([]*command{
		{
			"DNS Redirection",
			exec.Command("iptables", "-t", "nat", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "DNAT", "--to-destination", "192.168.100.1:53"),
			[]uintptr{uintptr(unix.CAP_NET_ADMIN)},
		},
		{
			"DNS Redirection",
			exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-p", "udp", "--dport", "53", "-d", "192.168.100.1", "-j", "SNAT", "--to-source", "192.168.100.2"),
			[]uintptr{uintptr(unix.CAP_NET_ADMIN)},
		},
		{
			"DNS Redirection",
			exec.Command("sysctl", "-w", "net.ipv4.conf.all.route_localnet=1"),
			[]uintptr{uintptr(unix.CAP_NET_ADMIN)},
		},
	})
	if err := runner.run(); err != nil {
		return err
	}

	return nil
}
