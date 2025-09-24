package cli

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
	"github.com/coder/boundary/rules"
	"github.com/coder/boundary/tls"
	"github.com/coder/boundary/util"
	"github.com/coder/serpent"
)

// Config holds all configuration for the CLI
type Config struct {
	AllowStrings []string
	LogLevel     string
	Unprivileged bool
}

// NewCommand creates and returns the root serpent command
func NewCommand() *serpent.Command {
	// To make the top level boundary command, we just make some minor changes to the base command
	cmd := BaseCommand()
	cmd.Use = "boundary [flags] -- command [args...]" // Add the flags and args pieces to usage.

	// Add example usage to the long description. This is different from usage as a subcommand because it
	// may be called something different when used as a subcommand / there will be a leading binary (i.e. `coder boundary` vs. `boundary`).
	cmd.Long += `Examples:
  # Allow only requests to github.com
  boundary --allow "github.com" -- curl https://github.com

  # Monitor all requests to specific domains (allow only those)
  boundary --allow "github.com/api/issues/*" --allow "GET,HEAD github.com" -- npm install

  # Block everything by default (implicit)`

	return cmd
}

// Base command returns the boundary serpent command without the information involved in making it the
// *top level* serpent command. We are creating this split to make it easier to integrate into the coder
// CLI if needed.
func BaseCommand() *serpent.Command {
	config := Config{}

	return &serpent.Command{
		Use:   "boundary",
		Short: "Network isolation tool for monitoring and restricting HTTP/HTTPS requests",
		Long:  `boundary creates an isolated network environment for target processes, intercepting HTTP/HTTPS traffic through a transparent proxy that enforces user-defined allow rules.`,
		Options: []serpent.Option{
			serpent.Option{
				Flag:        "allow",
				Env:         "BOUNDARY_ALLOW",
				Description: "Allow rule (repeatable). Format: \"pattern\" or \"METHOD[,METHOD] pattern\".",
				Value:       serpent.StringArrayOf(&config.AllowStrings),
			},
			serpent.Option{
				Flag:        "log-level",
				Env:         "BOUNDARY_LOG_LEVEL",
				Description: "Set log level (error, warn, info, debug).",
				Default:     "warn",
				Value:       serpent.StringOf(&config.LogLevel),
			},
			serpent.Option{
				Flag:        "unprivileged",
				Env:         "BOUNDARY_UNPRIVILEGED",
				Description: "Run in unprivileged mode (no network isolation, uses proxy environment variables).",
				Value:       serpent.BoolOf(&config.Unprivileged),
			},
		},
		Handler: func(inv *serpent.Invocation) error {
			args := inv.Args
			return Run(inv.Context(), config, args)
		},
	}
}

// Run executes the boundary command with the given configuration and arguments
func Run(ctx context.Context, config Config, args []string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	logger := setupLogging(config.LogLevel)
	username, uid, gid, homeDir, configDir := util.GetUserInfo()

	// Get command arguments
	if len(args) == 0 {
		return fmt.Errorf("no command specified")
	}

	// Parse allow list; default to deny-all if none provided
	if len(config.AllowStrings) == 0 {
		logger.Warn("No allow rules specified; all network traffic will be denied by default")
	}

	// Parse allow rules
	allowRules, err := rules.ParseAllowSpecs(config.AllowStrings)
	if err != nil {
		logger.Error("Failed to parse allow rules", "error", err)
		return fmt.Errorf("failed to parse allow rules: %v", err)
	}

	// Create rule engine
	ruleEngine := rules.NewRuleEngine(allowRules, logger)

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
	jailer, err := createJailer(jail.Config{
		Logger:        logger,
		HttpProxyPort: 8080,
		Username:      username,
		Uid:           uid,
		Gid:           gid,
		HomeDir:       homeDir,
		ConfigDir:     configDir,
		CACertPath:    caCertPath,
	}, config.Unprivileged)
	if err != nil {
		return fmt.Errorf("failed to create jailer: %v", err)
	}

	// Create boundary instance
	boundaryInstance, err := boundary.New(ctx, boundary.Config{
		RuleEngine: ruleEngine,
		Auditor:    auditor,
		TLSConfig:  tlsConfig,
		Logger:     logger,
		Jailer:     jailer,
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
		cmd := boundaryInstance.Command(args)
		cmd.Stderr = os.Stderr
		cmd.Stdout = os.Stdout
		cmd.Stdin = os.Stdin

		logger.Debug("Executing command in boundary", "command", strings.Join(args, " "))
		err := cmd.Run()
		if err != nil {
			logger.Error("Command execution failed", "error", err)
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

// setupLogging creates a slog logger with the specified level
func setupLogging(logLevel string) *slog.Logger {
	var level slog.Level
	switch strings.ToLower(logLevel) {
	case "error":
		level = slog.LevelError
	case "warn":
		level = slog.LevelWarn
	case "info":
		level = slog.LevelInfo
	case "debug":
		level = slog.LevelDebug
	default:
		level = slog.LevelWarn // Default to warn if invalid level
	}

	// Create a standard slog logger with the appropriate level
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	})

	return slog.New(handler)
}

// createJailer creates a new jail instance for the current platform
func createJailer(config jail.Config, unprivileged bool) (jail.Jailer, error) {
	if unprivileged {
		return jail.NewUnprivileged(config)
	}

	// Use the DefaultOS function for platform-specific jail creation
	return jail.DefaultOS(config)
}
