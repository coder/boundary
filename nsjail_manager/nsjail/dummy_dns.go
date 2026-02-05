package nsjail

import (
	"log/slog"
	"os/exec"

	"github.com/coder/boundary/dnsdummy"
	"golang.org/x/sys/unix"
)

// StartDummyDNSAndRedirect starts a dummy DNS server in-process (goroutine) listening on
// 127.0.0.1:5353 and redirects all DNS traffic (UDP/TCP port 53) in the namespace to it
// via iptables. This prevents DNS exfiltration: all DNS queries get a dummy response (6.6.6.6).
// Must be called from inside the network namespace.
func StartDummyDNSAndRedirect(logger *slog.Logger) error {
	addr := "127.0.0.1:" + dnsdummy.DefaultDummyDNSPort
	server := dnsdummy.NewServer(addr, logger)
	server.ListenAndServe()
	logger.Debug("dummy DNS server started in-process", "addr", addr)

	// Redirect all DNS (UDP and TCP port 53) to 127.0.0.1:5353
	runner := newCommandRunner([]*command{
		// Allow loopback-destined traffic to pass through NAT so DNAT to 127.0.0.1 works.
		// Best-effort: in some environments (e.g. Sysbox/Docker) this command may not work,
		// but DNS setup should work anyway.
		newCommandWithIgnoreErr(
			"Allow loopback-destined traffic for dummy DNS (route_localnet)",
			exec.Command("sysctl", "-w", "net.ipv4.conf.all.route_localnet=1"),
			[]uintptr{uintptr(unix.CAP_NET_ADMIN)},
			"*",
		),
		newCommand(
			"Redirect UDP DNS to dummy server",
			exec.Command("iptables", "-t", "nat", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "DNAT", "--to-destination", addr),
			[]uintptr{uintptr(unix.CAP_NET_ADMIN)},
		),
		newCommand(
			"Redirect TCP DNS to dummy server",
			exec.Command("iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", "DNAT", "--to-destination", addr),
			[]uintptr{uintptr(unix.CAP_NET_ADMIN)},
		),
		// Restrict all other UDP: allow only UDP to/from loopback (dummy DNS); drop everything else.
		// Allow UDP to 127.0.0.1 (query to dummy DNS) and UDP from 127.0.0.1 (reply from dummy DNS to client).
		newCommand(
			"Allow UDP to loopback (dummy DNS query)",
			exec.Command("iptables", "-A", "OUTPUT", "-p", "udp", "-d", "127.0.0.1", "-j", "ACCEPT"),
			[]uintptr{uintptr(unix.CAP_NET_ADMIN)},
		),
		newCommand(
			"Allow UDP from loopback (dummy DNS reply to client)",
			exec.Command("iptables", "-A", "OUTPUT", "-p", "udp", "-s", "127.0.0.1", "-j", "ACCEPT"),
			[]uintptr{uintptr(unix.CAP_NET_ADMIN)},
		),
		newCommand(
			"Drop all other UDP",
			exec.Command("iptables", "-A", "OUTPUT", "-p", "udp", "-j", "DROP"),
			[]uintptr{uintptr(unix.CAP_NET_ADMIN)},
		),
	})
	if err := runner.run(); err != nil {
		return err
	}

	return nil
}
