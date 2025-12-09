package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/coder/boundary"
	"github.com/coder/boundary/audit"
	"github.com/coder/boundary/jail"
	"github.com/coder/boundary/rulesengine"
	"github.com/coder/boundary/tls"
	"github.com/coder/boundary/util"
)

func RunParent(ctx context.Context, logger *slog.Logger, args []string, config Config) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	username, uid, gid, homeDir, configDir := util.GetUserInfo()

	// Get command arguments
	if len(args) == 0 {
		return fmt.Errorf("no command specified")
	}

	// Merge allowlist from config file with allow from CLI flags
	allowListStrings := config.AllowListStrings.Value()
	allowStrings := config.AllowStrings.Value()

	// Combine allowlist (config file) with allow (CLI flags)
	allAllowStrings := append(allowListStrings, allowStrings...)

	if len(allAllowStrings) == 0 {
		logger.Warn("No allow rules specified; all network traffic will be denied by default")
	}

	// Parse allow rules
	allowRules, err := rulesengine.ParseAllowSpecs(allAllowStrings)
	if err != nil {
		logger.Error("Failed to parse allow rules", "error", err)
		return fmt.Errorf("failed to parse allow rules: %v", err)
	}

	// Create rule engine
	ruleEngine := rulesengine.NewRuleEngine(allowRules, logger)

	// Create auditor
	auditor := audit.NewLogAuditor(logger)

	// Create TLS certificate manager
	certManager, err := tls.NewCertificateManager(tls.Config{
		Logger:    logger,
		ConfigDir: configDir,
		Uid:       uid,
		Gid:       gid,
	})
	if err != nil {
		logger.Error("Failed to create certificate manager", "error", err)
		return fmt.Errorf("failed to create certificate manager: %v", err)
	}

	// Setup TLS to get cert path for jailer
	tlsConfig, caCertPath, configDir, err := certManager.SetupTLSAndWriteCACert()
	if err != nil {
		return fmt.Errorf("failed to setup TLS and CA certificate: %v", err)
	}

	// Create jailer with cert path from TLS setup
	jailer, err := jail.NewLinuxJail(jail.Config{
		Logger:                     logger,
		HttpProxyPort:              int(config.ProxyPort.Value()),
		Username:                   username,
		Uid:                        uid,
		Gid:                        gid,
		HomeDir:                    homeDir,
		ConfigDir:                  configDir,
		CACertPath:                 caCertPath,
		ConfigureDNSForLocalStubResolver: config.ConfigureDNSForLocalStubResolver.Value(),
	})
	if err != nil {
		return fmt.Errorf("failed to create jailer: %v", err)
	}

	// Create boundary instance
	boundaryInstance, err := boundary.New(ctx, boundary.Config{
		RuleEngine:   ruleEngine,
		Auditor:      auditor,
		TLSConfig:    tlsConfig,
		Logger:       logger,
		Jailer:       jailer,
		ProxyPort:    int(config.ProxyPort.Value()),
		PprofEnabled: config.PprofEnabled.Value(),
		PprofPort:    int(config.PprofPort.Value()),
	})
	if err != nil {
		return fmt.Errorf("failed to create boundary instance: %v", err)
	}

	// Setup signal handling BEFORE any setup
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Open boundary (starts network namespace and proxy server)
	err = boundaryInstance.Start()
	if err != nil {
		return fmt.Errorf("failed to open boundary: %v", err)
	}
	defer func() {
		logger.Info("Closing boundary...")
		err := boundaryInstance.Close()
		if err != nil {
			logger.Error("Failed to close boundary", "error", err)
		}
	}()

	// Execute command in boundary
	go func() {
		defer cancel()
		cmd := boundaryInstance.Command(os.Args)

		logger.Debug("Executing command in boundary", "command", strings.Join(os.Args, " "))
		err := cmd.Start()
		if err != nil {
			logger.Error("Command failed to start", "error", err)
			return
		}

		err = boundaryInstance.ConfigureAfterCommandExecution(cmd.Process.Pid)
		if err != nil {
			logger.Error("configuration after command execution failed", "error", err)
			return
		}

		logger.Debug("waiting on a child process to finish")
		err = cmd.Wait()
		if err != nil {
			// Check if this is a normal exit with non-zero status code
			if exitError, ok := err.(*exec.ExitError); ok {
				exitCode := exitError.ExitCode()
				// Log at debug level for non-zero exits (normal behavior)
				logger.Debug("Command exited with non-zero status", "exit_code", exitCode)
			} else {
				// This is an unexpected error (not just a non-zero exit)
				logger.Error("Command execution failed", "error", err)
			}
			return
		}
		logger.Debug("Command completed successfully")
	}()

	// Wait for signal or context cancellation
	select {
	case sig := <-sigChan:
		logger.Info("Received signal, shutting down...", "signal", sig)
		cancel()
	case <-ctx.Done():
		// Context cancelled by command completion
		logger.Info("Command completed, shutting down...")
	}

	return nil
}
