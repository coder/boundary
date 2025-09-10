package cli

import (
	"context"
	cryptotls "crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/coder/jail"
	"github.com/coder/jail/audit"
	"github.com/coder/jail/namespace"
	"github.com/coder/jail/proxy"
	"github.com/coder/jail/rules"
	"github.com/coder/jail/tls"
	"github.com/coder/serpent"
)

// Config holds all configuration for the CLI
type Config struct {
	AllowStrings   []string
	NoTLSIntercept bool
	LogLevel       string
}

// NewCommand creates and returns the root serpent command
func NewCommand() *serpent.Command {
	var config Config

	return &serpent.Command{
		Use:   "jail [flags] -- command [args...]",
		Short: "Monitor and restrict HTTP/HTTPS requests from processes",
		Long: `jail creates an isolated network environment for the target process,
intercepting all HTTP/HTTPS traffic through a transparent proxy that enforces
user-defined rules.

Examples:
  # Allow only requests to github.com
  jail --allow "github.com" -- curl https://github.com

  # Monitor all requests to specific domains (allow only those)
  jail --allow "github.com/api/issues/*" --allow "GET,HEAD github.com" -- npm install

  # Block everything by default (implicit)`,
		Options: serpent.OptionSet{
			{
				Name:        "allow",
				Flag:        "allow",
				Env:         "JAIL_ALLOW",
				Description: "Allow rule (can be specified multiple times). Format: 'pattern' or 'METHOD[,METHOD] pattern'.",
				Value:       serpent.StringArrayOf(&config.AllowStrings),
			},
			{
				Name:        "no-tls-intercept",
				Flag:        "no-tls-intercept",
				Env:         "JAIL_NO_TLS_INTERCEPT",
				Description: "Disable HTTPS interception.",
				Value:       serpent.BoolOf(&config.NoTLSIntercept),
			},
			{
				Name:        "log-level",
				Flag:        "log-level",
				Env:         "JAIL_LOG_LEVEL",
				Description: "Set log level (error, warn, info, debug).",
				Default:     "warn",
				Value:       serpent.StringOf(&config.LogLevel),
			},
		},
		Handler: func(inv *serpent.Invocation) error {
			return Run(config, inv.Args)
		},
	}
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

// Run executes the jail command with the given configuration and arguments
func Run(config Config, args []string) error {
	logger := setupLogging(config.LogLevel)

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
	auditor := audit.NewLoggingAuditor(logger)

	// Create network namespace configuration
	nsConfig := namespace.Config{
		HTTPPort:  8040,
		HTTPSPort: 8043,
	}

	// Create commander
	commander, err := namespace.New(nsConfig, logger)
	if err != nil {
		logger.Error("Failed to create network namespace", "error", err)
		return fmt.Errorf("failed to create network namespace: %v", err)
	}

	// Create certificate manager (if TLS interception is enabled)
	var tlsConfig *cryptotls.Config
	if !config.NoTLSIntercept {
		certManager, err := tls.NewCertificateManager(logger)
		if err != nil {
			logger.Error("Failed to create certificate manager", "error", err)
			return fmt.Errorf("failed to create certificate manager: %v", err)
		}

		// Setup TLS config and write CA certificate to file
		var caCertPath, configDir string
		tlsConfig, caCertPath, configDir, err = certManager.SetupTLSAndWriteCACert()
		if err != nil {
			logger.Error("Failed to setup TLS and CA certificate", "error", err)
			return fmt.Errorf("failed to setup TLS and CA certificate: %v", err)
		}

		// Set standard CA certificate environment variables for common tools
		// This makes tools like curl, git, etc. trust our dynamically generated CA
		commander.SetEnv("SSL_CERT_FILE", caCertPath)       // OpenSSL/LibreSSL-based tools
		commander.SetEnv("SSL_CERT_DIR", configDir)         // OpenSSL certificate directory
		commander.SetEnv("CURL_CA_BUNDLE", caCertPath)      // curl
		commander.SetEnv("GIT_SSL_CAINFO", caCertPath)      // Git
		commander.SetEnv("REQUESTS_CA_BUNDLE", caCertPath)  // Python requests
		commander.SetEnv("NODE_EXTRA_CA_CERTS", caCertPath) // Node.js
	}

	// Create proxy server
	proxyServer := proxy.NewProxyServer(proxy.Config{
		HTTPPort:   8040,
		HTTPSPort:  8043,
		RuleEngine: ruleEngine,
		Auditor:    auditor,
		Logger:     logger,
		TLSConfig:  tlsConfig,
	})

	// Create jail instance
	jailInstance := jail.New(jail.Config{
		Commander:   commander,
		ProxyServer: proxyServer,
		Logger:      logger,
	})

	// Setup signal handling BEFORE any setup
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Handle signals immediately in background
	go func() {
		sig := <-sigChan
		logger.Info("Received signal during setup, cleaning up...", "signal", sig)
		err := jailInstance.Close()
		if err != nil {
			logger.Error("Emergency cleanup failed", "error", err)
		}
		os.Exit(1)
	}()

	// Ensure cleanup happens no matter what
	defer func() {
		logger.Debug("Starting cleanup process")
		err := jailInstance.Close()
		if err != nil {
			logger.Error("Failed to cleanup jail", "error", err)
		} else {
			logger.Debug("Cleanup completed successfully")
		}
	}()

	// Open jail (starts network namespace and proxy server)
	err = jailInstance.Open()
	if err != nil {
		logger.Error("Failed to open jail", "error", err)
		return fmt.Errorf("failed to open jail: %v", err)
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Execute command in jail
	go func() {
		defer cancel()
		err := jailInstance.Command(args).Run()
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
