package jail

import (
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

type Jailer interface {
	ConfigureBeforeCommandExecution() error
	Command(command []string) *exec.Cmd
	ConfigureAfterCommandExecution(processPID int) error
	Close() error
}

type Config struct {
	Logger        *slog.Logger
	HttpProxyPort int
	Username      string
	Uid           int
	Gid           int
	HomeDir       string
	ConfigDir     string
	CACertPath    string
}

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

	cmd := exec.Command(command[0], command[1:]...)
	cmd.Env = l.commandEnv
	cmd.Env = append(cmd.Env, "CHILD=true")
	cmd.Env = append(cmd.Env, fmt.Sprintf("VETH_JAIL_NAME=%v", l.vethJailName))
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin

	l.logger.Debug("os.Getuid()", "os.Getuid()", os.Getuid())
	l.logger.Debug("os.Getgid()", "os.Getgid()", os.Getgid())
	currentUid := os.Getuid()
	currentGid := os.Getgid()

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: currentUid, HostID: currentUid, Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: currentGid, HostID: currentGid, Size: 1},
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
