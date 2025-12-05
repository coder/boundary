package app

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/coder/boundary/jail"
	"golang.org/x/sys/unix"
)

// waitForInterface waits for a network interface to appear in the namespace.
// It retries checking for the interface with exponential backoff up to the specified timeout.
func waitForInterface(interfaceName string, timeout time.Duration) error {
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = 50 * time.Millisecond
	b.MaxInterval = 500 * time.Millisecond
	b.Multiplier = 2.0

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	operation := func() (bool, error) {
		cmd := exec.Command("ip", "link", "show", interfaceName)
		cmd.SysProcAttr = &syscall.SysProcAttr{
			AmbientCaps: []uintptr{uintptr(unix.CAP_NET_ADMIN)},
		}

		err := cmd.Run()
		if err != nil {
			return false, fmt.Errorf("interface %s not found: %w", interfaceName, err)
		}
		// Interface exists
		return true, nil
	}

	_, err := backoff.Retry(ctx, operation, backoff.WithBackOff(b))
	if err != nil {
		return fmt.Errorf("interface %s did not appear within %v: %w", interfaceName, timeout, err)
	}

	return nil
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

	err = jail.ConfigureDNSForLocalStubResolver()
	if err != nil {
		return fmt.Errorf("failed to configure DNS in namespace: %v", err)
	}
	logger.Info("DNS in namespace is configured successfully")

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
