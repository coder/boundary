package app

import (
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/exec"

	"github.com/coder/boundary/jail"
)

func RunChild(logger *slog.Logger, args []string) error {
	logger.Info("boundary CHILD process is started")

	vethNetJail := os.Getenv("VETH_JAIL_NAME")
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
