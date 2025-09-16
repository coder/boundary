package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/coder/jail"
	"github.com/coder/jail/audit"
	"github.com/coder/jail/namespace"
	"github.com/coder/jail/rules"
	"github.com/coder/jail/tls"
	"github.com/coder/serpent"
)

// Config holds all configuration for the CLI
type Config struct {
	AllowStrings []string
	LogLevel     string
}

// NewCommand creates and returns the root serpent command
func NewCommand() *serpent.Command {
	// To make the top level jail command, we just make some minor changes to the base command
	cmd := BaseCommand()
	cmd.Use = "jail [flags] -- command [args...]" // Add the flags and args pieces to usage.

	// Add example usage to the long description. This is different from usage as a subcommand because it
	// may be called something different when used as a subcommand / there will be a leading binary (i.e. `coder jail` vs. `jail`).
	cmd.Long += `Examples:
  # Allow only requests to github.com
  jail --allow "github.com" -- curl https://github.com

  # Monitor all requests to specific domains (allow only those)
  jail --allow "github.com/api/issues/*" --allow "GET,HEAD github.com" -- npm install

  # Block everything by default (implicit)`

	return cmd
}

// Base command returns the jail serpent command without the information involved in making it the
// *top level* serpent command. We are creating this split to make it easier to integrate into the coder
// cli without introducing sources of drift.
func BaseCommand() *serpent.Command {
	var config Config

	return &serpent.Command{
		Use:   "jail -- command",
		Short: "Monitor and restrict HTTP/HTTPS requests from processes",
		Long: `creates an isolated network environment for the target process,
intercepting all HTTP/HTTPS traffic through a transparent proxy that enforces
user-defined rules.`,
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

// Run executes the jail command with the given configuration and arguments
func Run(ctx context.Context, config Config, args []string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	logger := setupLogging(config.LogLevel)
	userInfo := getUserInfo()

	// Get command arguments
	if len(args) == 0 {
		return fmt.Errorf("no command specified")
	}

	// Parse allow list; default to deny-all if none provided
	if len(config.AllowStrings) == 0 {
		logger.Warn("No allow rules specified; all network traffic will be denied by default")
	}

	// Parse allow rules
	allowRules := []rules.Rule{}
	for _, allowStr := range config.AllowStrings {
		rule, err := rules.ParseRule(allowStr)
		if err != nil {
			logger.Error("Failed to parse allow rule", "error", err)
			return fmt.Errorf("failed to parse allow rule: %v", err)
		}
		allowRules = append(allowRules, rule)
	}

	// Create rule engine
	ruleEngine := rules.NewEngine(allowRules, logger)

	// Create auditor
	auditor := audit.NewLoggingAuditor(logger)

	// Create certificate manager
	certManager, err := tls.NewCertificateManager(tls.Config{
		Logger:    logger,
		ConfigDir: userInfo.ConfigDir,
	})
	if err != nil {
		logger.Error("Failed to create certificate manager", "error", err)
		return fmt.Errorf("failed to create certificate manager: %v", err)
	}

	// Create jail instance
	jailInstance, err := jail.New(ctx, jail.Config{
		RuleEngine:  ruleEngine,
		Auditor:     auditor,
		CertManager: certManager,
		Logger:      logger,
	})
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

func getUserInfo() namespace.UserInfo {
	// get the user info of the original user even if we are running under sudo
	sudoUser := os.Getenv("SUDO_USER")

	// If running under sudo, get original user information
	if sudoUser != "" {
		user, err := user.Lookup(sudoUser)
		if err != nil {
			// Fallback to current user if lookup fails
			return getCurrentUserInfo()
		}

		// Parse SUDO_UID and SUDO_GID
		uid := 0
		gid := 0

		if sudoUID := os.Getenv("SUDO_UID"); sudoUID != "" {
			if parsedUID, err := strconv.Atoi(sudoUID); err == nil {
				uid = parsedUID
			}
		}

		if sudoGID := os.Getenv("SUDO_GID"); sudoGID != "" {
			if parsedGID, err := strconv.Atoi(sudoGID); err == nil {
				gid = parsedGID
			}
		}

		configDir := getConfigDir(user.HomeDir)

		return namespace.UserInfo{
			Username:  sudoUser,
			Uid:       uid,
			Gid:       gid,
			HomeDir:   user.HomeDir,
			ConfigDir: configDir,
		}
	}

	// Not running under sudo, use current user
	return getCurrentUserInfo()
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

// getCurrentUserInfo gets information for the current user
func getCurrentUserInfo() namespace.UserInfo {
	currentUser, err := user.Current()
	if err != nil {
		// Fallback with empty values if we can't get user info
		return namespace.UserInfo{}
	}

	uid, _ := strconv.Atoi(currentUser.Uid)
	gid, _ := strconv.Atoi(currentUser.Gid)

	configDir := getConfigDir(currentUser.HomeDir)

	return namespace.UserInfo{
		Username:  currentUser.Username,
		Uid:       uid,
		Gid:       gid,
		HomeDir:   currentUser.HomeDir,
		ConfigDir: configDir,
	}
}

// getConfigDir determines the config directory based on XDG_CONFIG_HOME or fallback
func getConfigDir(homeDir string) string {
	// Use XDG_CONFIG_HOME if set, otherwise fallback to ~/.config/coder_jail
	if xdgConfigHome := os.Getenv("XDG_CONFIG_HOME"); xdgConfigHome != "" {
		return filepath.Join(xdgConfigHome, "coder_jail")
	}
	return filepath.Join(homeDir, ".config", "coder_jail")
}
