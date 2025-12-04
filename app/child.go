package app

import (
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/coder/boundary/jail"
)

// waitForInterface waits for a network interface to appear in the namespace.
// It retries checking for the interface with exponential backoff up to the specified timeout.
func waitForInterface(interfaceName string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	interval := 50 * time.Millisecond // Start with 50ms intervals
	maxInterval := 500 * time.Millisecond

	for time.Now().Before(deadline) {
		cmd := exec.Command("ip", "link", "show", interfaceName)
		cmd.SysProcAttr = &syscall.SysProcAttr{
			AmbientCaps: []uintptr{uintptr(unix.CAP_NET_ADMIN)},
		}

		err := cmd.Run()
		if err == nil {
			// Interface exists
			return nil
		}

		// Wait before next attempt
		time.Sleep(interval)

		// Exponential backoff, but cap at maxInterval
		interval *= 2
		if interval > maxInterval {
			interval = maxInterval
		}
	}

	return fmt.Errorf("interface %s did not appear within %v", interfaceName, timeout)
}

func RunChild(logger *slog.Logger, args []string) error {
	logger.Info("boundary CHILD process is started")

	vethNetJail := os.Getenv("VETH_JAIL_NAME")
	if vethNetJail == "" {
		return fmt.Errorf("VETH_JAIL_NAME environment variable is not set")
	}

	// Wait for the veth interface to be moved into the namespace by the parent process
	if err := waitForInterface(vethNetJail, 5*time.Second); err != nil {
		return fmt.Errorf("failed to wait for interface %s: %w", vethNetJail, err)
	}

	err := jail.SetupChildNetworking(vethNetJail)
	if err != nil {
		return fmt.Errorf("failed to setup child networking: %v", err)
	}
	logger.Info("child networking is successfully configured")

	err = jail.ConfigureDNSInNamespace()
	if err != nil {
		return fmt.Errorf("failed to configure DNS in namespace: %v", err)
	}

	// Program to run
	bin := args[0]
	args = args[1:]

	cmd := exec.Command(bin, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		log.Printf("failed to run %s: %v", bin, err)
		return err
	}

	return nil
}
