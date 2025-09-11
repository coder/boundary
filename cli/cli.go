package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"syscall"

	"github.com/coder/jail"
	"github.com/coder/jail/audit"
	"github.com/coder/jail/rules"
	"github.com/coder/jail/tls"
	"github.com/coder/serpent"
)

// SudoData contains processed sudo environment information
type SudoData struct {
	// Processed values
	IsUnderSudo   bool
	UserInfo      *user.User // Original user info when under sudo
	UID           int        // Parsed UID, 0 if not available
	GID           int        // Parsed GID, 0 if not available
	XDGConfigHome string     // XDG config home directory
}

// ToTLSEnvConfig converts SudoData to tls.EnvConfig
func (s SudoData) ToTLSEnvConfig() tls.EnvConfig {
	sudoUser := ""
	if s.UserInfo != nil {
		sudoUser = s.UserInfo.Username
	}
	return tls.EnvConfig{
		SudoUser:      sudoUser,
		SudoUID:       s.UID,
		SudoGID:       s.GID,
		XDGConfigHome: s.XDGConfigHome,
	}
}

// ToJailEnvConfig converts SudoData to jail.EnvConfig
func (s SudoData) ToJailEnvConfig() jail.EnvConfig {
	sudoUser := ""
	if s.UserInfo != nil {
		sudoUser = s.UserInfo.Username
	}
	return jail.EnvConfig{
		SudoUser: sudoUser,
		SudoUID:  s.UID,
		SudoGID:  s.GID,
	}
}

// readSudoData reads and processes sudo-related environment variables
func readSudoData(logger *slog.Logger) SudoData {
	// Read raw environment values
	sudoUser := os.Getenv("SUDO_USER")
	sudoUID := os.Getenv("SUDO_UID")
	sudoGID := os.Getenv("SUDO_GID")
	xdgConfigHome := os.Getenv("XDG_CONFIG_HOME")
	
	data := SudoData{
		IsUnderSudo:   sudoUser != "",
		XDGConfigHome: xdgConfigHome,
	}
	
	// Process user information if under sudo
	if data.IsUnderSudo {
		if userInfo, err := user.Lookup(sudoUser); err == nil {
			data.UserInfo = userInfo
			logger.Debug("Found original user info", "user", sudoUser, "home", userInfo.HomeDir)
		} else {
			logger.Warn("Failed to lookup original user", "user", sudoUser, "error", err)
		}
		
		// Parse UID
		if sudoUID != "" {
			if uid, err := strconv.Atoi(sudoUID); err == nil {
				data.UID = uid
			} else {
				logger.Warn("Invalid SUDO_UID, using 0", "sudo_uid", sudoUID, "error", err)
			}
		}
		
		// Parse GID
		if sudoGID != "" {
			if gid, err := strconv.Atoi(sudoGID); err == nil {
				data.GID = gid
			} else {
				logger.Warn("Invalid SUDO_GID, using 0", "sudo_gid", sudoGID, "error", err)
			}
		}
	}
	
	return data
}

// Config holds all configuration for the CLI
type Config struct {
	AllowStrings []string
	LogLevel     string
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
				Name:        "log-level",
				Flag:        "log-level",
				Env:         "JAIL_LOG_LEVEL",
				Description: "Set log level (error, warn, info, debug).",
				Default:     "warn",
				Value:       serpent.StringOf(&config.LogLevel),
			},
		},
		Handler: func(inv *serpent.Invocation) error {
			return Run(inv.Context(), config, inv.Args)
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
func Run(ctx context.Context, config Config, args []string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	logger := setupLogging(config.LogLevel)

	// Read and process sudo environment data once
	sudoData := readSudoData(logger)

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

	// Create certificate manager with environment variables
	certManager, err := tls.NewCertificateManager(logger, sudoData.ToTLSEnvConfig())
	if err != nil {
		logger.Error("Failed to create certificate manager", "error", err)
		return fmt.Errorf("failed to create certificate manager: %v", err)
	}

	// Create jail instance with environment variables
	jailInstance, err := jail.New(ctx, jail.Config{
		RuleEngine:  ruleEngine,
		Auditor:     auditor,
		CertManager: certManager,
		Logger:      logger,
	}, sudoData.ToJailEnvConfig())
	if err != nil {
		return fmt.Errorf("failed to create jail instance: %v", err)
	}

	// Setup signal handling BEFORE any setup
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Open jail (starts network namespace and proxy server)
	err = jailInstance.Start()
	if err != nil {
		return fmt.Errorf("failed to open jail: %v", err)
	}
	defer func() {
		logger.Info("Closing jail...")
		err := jailInstance.Close()
		if err != nil {
			logger.Error("Failed to close jail", "error", err)
		}
	}()

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