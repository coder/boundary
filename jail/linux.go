//go:build linux

package jail

import (
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/coder/boundary/util"
	"golang.org/x/sys/unix"
)

// LinuxJail implements Jailer using Linux network namespaces
type LinuxJail struct {
	logger        *slog.Logger
	vethHostName  string // Host-side veth interface name for iptables rules
	vethJailName  string // Jail-side veth interface name for iptables rules
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
		httpProxyPort: config.HttpProxyPort,
		configDir:     config.ConfigDir,
		caCertPath:    config.CACertPath,
		homeDir:       config.HomeDir,
		username:      config.Username,
		uid:           config.Uid,
		gid:           config.Gid,
	}, nil
}

// ConfigureBeforeCommandExecution prepares the jail environment before the target
// process is launched. It sets environment variables, creates the veth pair, and
// installs iptables rules on the host. At this stage, the target PID and its netns
// are not yet known.
func (l *LinuxJail) ConfigureBeforeCommandExecution() error {
	l.commandEnv = getEnvs(l.configDir, l.caCertPath)

	if err := l.configureHostNetworkBeforeCmdExec(); err != nil {
		return err
	}
	if err := l.configureIptables(); err != nil {
		return fmt.Errorf("failed to configure iptables: %v", err)
	}

	return nil
}

// Command returns an exec.Cmd configured to run within the network namespace.
func (l *LinuxJail) Command(command []string) *exec.Cmd {
	l.logger.Debug("Creating command with namespace")

	l.logger.Debug("DEBUG", "command[0 ]", command[0])
	l.logger.Debug("DEBUG", "command[1:]", command[1:])

	cmd := exec.Command(command[0], command[1:]...)
	cmd.Env = l.commandEnv
	cmd.Env = append(cmd.Env, "CHILD=true")
	cmd.Env = append(cmd.Env, fmt.Sprintf("VETH_JAIL_NAME=%v", l.vethJailName))
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin

	l.logger.Debug("os.Getuid()", "os.Getuid()", os.Getuid())
	_, uid, gid, _, _ := util.GetUserInfo()

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: 0, Size: 1},
			{ContainerID: uid, HostID: uid, Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: 0, Size: 1},
			{ContainerID: gid, HostID: gid, Size: 1},
		},
		AmbientCaps: []uintptr{unix.CAP_NET_ADMIN},
	}

	return cmd
}

// ConfigureAfterCommandExecution finalizes setup once the target process starts.
// With the child PID known, it moves the jail-side veth into the child’s network
// namespace.
func (l *LinuxJail) ConfigureAfterCommandExecution(pidInt int) error {
	err := l.configureHostNetworkAfterCmdExec(pidInt)
	if err != nil {
		return fmt.Errorf("failed to configure parent networking: %v", err)
	}

	return nil
}

// Close removes the network namespace and iptables rules
func (l *LinuxJail) Close() error {
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

	return nil
}

type command struct {
	description string
	cmd         *exec.Cmd
	ambientCaps []uintptr
}

type commandRunner struct {
	commands []*command
}

func newCommandRunner(commands []*command) *commandRunner {
	return &commandRunner{
		commands: commands,
	}
}

func (r *commandRunner) run() error {
	for _, command := range r.commands {
		command.cmd.SysProcAttr = &syscall.SysProcAttr{
			AmbientCaps: command.ambientCaps,
		}

		output, err := command.cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to %s: %v, output: %s", command.description, err, output)
		}
	}

	return nil
}

func (r *commandRunner) runIgnoreErrors() error {
	for _, command := range r.commands {
		command.cmd.SysProcAttr = &syscall.SysProcAttr{
			AmbientCaps: command.ambientCaps,
		}

		output, err := command.cmd.CombinedOutput()
		if err != nil {
			log.Printf("failed to %s: %v, output: %s", command.description, err, output)
			continue
		}
	}

	return nil
}

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
