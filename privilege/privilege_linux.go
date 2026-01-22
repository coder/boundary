//go:build linux

package privilege

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
)

// EnsurePrivileges ensures the process has the necessary privileges (CAP_NET_ADMIN and optionally CAP_SYS_ADMIN).
// If not running with sufficient privileges, it re-executes itself with sudo + setpriv.
// This function should be called early in main() before any privileged operations.
// Assumes the process is always started as a regular user.
func EnsurePrivileges() error {
	// Check if we're already in the process of privilege escalation (to prevent infinite loops)
	if os.Getenv("BOUNDARY_PRIV_ESCALATED") == "1" {
		// We've already escalated, continue
		return nil
	}

	// If we're already root, something went wrong (we shouldn't be root as a regular user)
	// But continue anyway to avoid breaking existing setups
	if os.Geteuid() == 0 {
		return nil
	}

	// Not root, need to re-exec with sudo + setpriv
	return reExecWithPrivileges()
}

// reExecWithPrivileges re-executes the current binary with sudo + setpriv
func reExecWithPrivileges() error {
	// Find sudo binary
	sudoPath, err := exec.LookPath("sudo")
	if err != nil {
		return fmt.Errorf("sudo not found in PATH. Please run with sudo or install sudo: %w", err)
	}

	// Find setpriv binary
	setprivPath, err := exec.LookPath("setpriv")
	if err != nil {
		return fmt.Errorf("setpriv not found in PATH. Please install util-linux: %w", err)
	}

	// Get current user
	currentUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}

	uid, err := strconv.Atoi(currentUser.Uid)
	if err != nil {
		return fmt.Errorf("failed to parse UID: %w", err)
	}

	gid, err := strconv.Atoi(currentUser.Gid)
	if err != nil {
		return fmt.Errorf("failed to parse GID: %w", err)
	}

	// Get current binary path
	binaryPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	// Get current args (skip program name)
	args := os.Args[1:]

	// Build sudo command: sudo -E env PATH=$PATH setpriv --reuid=UID --regid=GID --clear-groups --inh-caps=+net_admin,+sys_admin --ambient-caps=+net_admin,+sys_admin binary args...
	cmd := exec.Command(sudoPath,
		"-E",
		"env",
		"PATH="+os.Getenv("PATH"),
		setprivPath,
		"--reuid", strconv.Itoa(uid),
		"--regid", strconv.Itoa(gid),
		"--clear-groups",
		"--inh-caps", "+net_admin,+sys_admin",
		"--ambient-caps", "+net_admin,+sys_admin",
		binaryPath,
	)
	cmd.Args = append(cmd.Args, args...)
	env := os.Environ()
	env = append(env, "BOUNDARY_PRIV_ESCALATED=1")
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Execute and replace current process
	return syscall.Exec(cmd.Path, cmd.Args, cmd.Env)
}

