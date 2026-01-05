package nojail

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/coder/boundary/audit"
	"github.com/coder/boundary/config"
	"github.com/coder/boundary/proxy"
	"github.com/coder/boundary/rulesengine"
)

type NoJail struct {
	proxyServer *proxy.Server
	logger      *slog.Logger
	config      config.AppConfig
}

func NewNoJail(
	ruleEngine rulesengine.Engine,
	auditor audit.Auditor,
	tlsConfig *tls.Config,
	logger *slog.Logger,
	config config.AppConfig,
) (*NoJail, error) {
	// Create proxy server
	proxyServer := proxy.NewProxyServer(proxy.Config{
		HTTPPort:     int(config.ProxyPort),
		RuleEngine:   ruleEngine,
		Auditor:      auditor,
		Logger:       logger,
		TLSConfig:    tlsConfig,
		PprofEnabled: config.PprofEnabled,
		PprofPort:    int(config.PprofPort),
	})

	return &NoJail{
		config:      config,
		proxyServer: proxyServer,
		logger:      logger,
	}, nil
}

func (n *NoJail) Run(ctx context.Context) error {
	n.logger.Info("Start nojail manager")
	err := n.startProxy()
	if err != nil {
		return fmt.Errorf("failed to start nojail manager: %v", err)
	}

	defer func() {
		n.logger.Info("Stop nojail manager")
		err := n.stopProxy()
		if err != nil {
			n.logger.Error("Failed to stop nojail manager", "error", err)
		}
	}()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		defer cancel()
		err := n.RunChildProcess(os.Args)
		if err != nil {
			n.logger.Error("Failed to run child process", "error", err)
		}
	}()

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for signal or context cancellation
	select {
	case sig := <-sigChan:
		n.logger.Info("Received signal, shutting down...", "signal", sig)
		cancel()
	case <-ctx.Done():
		// Context canceled by command completion
		n.logger.Info("Command completed, shutting down...")
	}

	return nil
}

func (n *NoJail) RunChildProcess(command []string) error {
	childCmd := n.getChildCommand(command)

	n.logger.Debug("Executing command in nojail mode", "command", strings.Join(os.Args, " "))
	err := childCmd.Start()
	if err != nil {
		n.logger.Error("Command failed to start", "error", err)
		return err
	}

	n.logger.Debug("waiting on a child process to finish")
	err = childCmd.Wait()
	if err != nil {
		// Check if this is a normal exit with non-zero status code
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode := exitError.ExitCode()
			// Log at debug level for non-zero exits (normal behavior)
			n.logger.Debug("Command exited with non-zero status", "exit_code", exitCode)
			return err
		}

		// This is an unexpected error (not just a non-zero exit)
		n.logger.Error("Command execution failed", "error", err)
		return err
	}
	n.logger.Debug("Command completed successfully")

	return nil
}

func (n *NoJail) getChildCommand(command []string) *exec.Cmd {
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Env = append(os.Environ(), "CHILD=true")
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin

	return cmd
}

func (n *NoJail) startProxy() error {
	// Start proxy server in background
	err := n.proxyServer.Start()
	if err != nil {
		n.logger.Error("Proxy server error", "error", err)
		return err
	}

	// Give proxy time to start
	time.Sleep(100 * time.Millisecond)

	return nil
}

func (n *NoJail) stopProxy() error {
	// Stop proxy server
	if n.proxyServer != nil {
		err := n.proxyServer.Stop()
		if err != nil {
			n.logger.Error("Failed to stop proxy server", "error", err)
		}
	}

	return nil
}
