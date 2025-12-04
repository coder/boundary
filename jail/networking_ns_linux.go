//go:build linux

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
