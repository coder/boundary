package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
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

// RunSimple runs boundary in simple mode using HTTP_PROXY environment variables
// instead of network namespaces. This mode doesn't require elevated privileges
// but only intercepts traffic from proxy-aware applications.
func RunSimple(ctx context.Context, logger *slog.Logger, args []string, config Config) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	_, uid, gid, _, configDir := util.GetUserInfo()

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

	// Create auditor - check for socket path to forward logs to agent
	var auditor audit.Auditor
	logAuditor := audit.NewLogAuditor(logger)

	socketPath := os.Getenv(BoundaryLogSocketEnvVar)
	workspaceIDStr := os.Getenv(BoundaryWorkspaceIDEnvVar)

	if socketPath != "" && workspaceIDStr != "" {
		// Parse workspace ID - it should be a UUID in standard format
		workspaceID, err := parseUUID(workspaceIDStr)
		if err != nil {
			logger.Warn("Invalid workspace ID, using local auditor only", "error", err)
			auditor = logAuditor
		} else {
			socketAuditor := audit.NewSocketAuditor(socketPath, workspaceID)
			auditor = audit.NewMultiAuditor(logAuditor, socketAuditor)
			logger.Info("Boundary log forwarding enabled",
				"socket_path", socketPath,
				"workspace_id", workspaceIDStr)
		}
	} else {
		auditor = logAuditor
	}

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

	// Create simple jailer (uses HTTP_PROXY instead of network namespaces)
	jailer, err := jail.NewSimpleJail(jail.Config{
		Logger:        logger,
		HttpProxyPort: int(config.ProxyPort.Value()),
		ConfigDir:     configDir,
		CACertPath:    caCertPath,
	})
	if err != nil {
		return fmt.Errorf("failed to create simple jailer: %v", err)
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

	// Open boundary (starts proxy server)
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

	logger.Info("Running in simple mode (HTTP_PROXY based)",
		"proxy_port", config.ProxyPort.Value())

	// Execute command with proxy environment
	go func() {
		defer cancel()
		cmd := boundaryInstance.Command(args)

		logger.Debug("Executing command with proxy environment", "command", strings.Join(args, " "))
		err := cmd.Start()
		if err != nil {
			logger.Error("Command failed to start", "error", err)
			return
		}

		// No post-start configuration needed for simple mode
		err = boundaryInstance.ConfigureAfterCommandExecution(cmd.Process.Pid)
		if err != nil {
			logger.Error("configuration after command execution failed", "error", err)
			return
		}

		logger.Debug("waiting on a child process to finish")
		err = cmd.Wait()
		if err != nil {
			logger.Error("Command execution failed", "error", err)
			return
		}
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
