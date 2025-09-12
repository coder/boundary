package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
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
	Unprivileged bool // Enable unprivileged mode (user namespace + iptables)
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

Modes:
  Default (privileged): Uses network namespaces + iptables (requires sudo)
  Unprivileged: Uses user namespaces + iptables (no sudo required)

Examples:
  # Privileged mode (original behavior)
  sudo jail --allow "github.com" -- curl https://github.com

  # Unprivileged mode (NEW!)
  jail --unprivileged --allow "github.com" -- curl https://github.com

  # Monitor all requests to specific domains
  jail --unprivileged --allow "github.com/api/issues/*" --allow "GET,HEAD github.com" -- npm install

  # Block everything by default (implicit)
  jail --unprivileged --allow "api.example.com" -- ./my-app`,
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
			{
				Name:        "unprivileged",
				Flag:        "unprivileged",
				Env:         "JAIL_UNPRIVILEGED",
				Description: "Use unprivileged mode (user namespace + iptables, no sudo required, Linux only).",
				Value:       serpent.BoolOf(&config.Unprivileged),
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

	// Validate unprivileged mode if requested
	if config.Unprivileged {
		// Warn if running as root but don't block it (some container environments need this)
		if os.Geteuid() == 0 {
			logger.Warn("Running unprivileged mode as root - this may cause permission issues with config files")
		}
		if err := validateUnprivilegedMode(logger); err != nil {
			return fmt.Errorf("unprivileged mode validation failed: %v", err)
		}
		logger.Info("Using unprivileged mode (user namespace + iptables, no sudo required)")
	} else {
		logger.Info("Using privileged mode (network namespace + iptables, requires sudo)")
	}

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
		RuleEngine:   ruleEngine,
		Auditor:      auditor,
		CertManager:  certManager,
		Logger:       logger,
		Unprivileged: config.Unprivileged,
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

// getUserInfo returns information about the current user, handling sudo scenarios
func getUserInfo() namespace.UserInfo {
	// Only consider SUDO_USER if we're actually running with elevated privileges
	// In environments like Coder workspaces, SUDO_USER may be set to 'root' 
	// but we're not actually running under sudo
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" && os.Geteuid() == 0 && sudoUser != "root" {
		// We're actually running under sudo with a non-root original user
		user, err := user.Lookup(sudoUser)
		if err != nil {
			return getCurrentUserInfo() // Fallback to current user
		}

		uid, _ := strconv.Atoi(os.Getenv("SUDO_UID"))
		gid, _ := strconv.Atoi(os.Getenv("SUDO_GID"))

		// If we couldn't get UID/GID from env, parse from user info
		if uid == 0 {
			if parsedUID, err := strconv.Atoi(user.Uid); err == nil {
				uid = parsedUID
			}
		}
		if gid == 0 {
			if parsedGID, err := strconv.Atoi(user.Gid); err == nil {
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

	// Not actually running under sudo, use current user
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

// validateUnprivilegedMode checks if the system supports unprivileged mode
func validateUnprivilegedMode(logger *slog.Logger) error {
	// Check if we're on Linux
	if runtime.GOOS != "linux" {
		return fmt.Errorf("unprivileged mode only supports Linux, got: %s", runtime.GOOS)
	}

	// Check if slirp4netns is available (required for user space networking)
	if _, err := exec.LookPath("slirp4netns"); err != nil {
		return fmt.Errorf("slirp4netns not found: %v\n\nInstall slirp4netns for unprivileged mode:\n  Ubuntu/Debian: sudo apt-get install slirp4netns\n  RHEL/CentOS: sudo yum install slirp4netns\n  Arch: sudo pacman -S slirp4netns\n  From source: https://github.com/rootless-containers/slirp4netns", err)
	}
	logger.Debug("slirp4netns found", "path", getSlirp4netnsPath())

	// Check if user namespaces are enabled
	userNSFile := "/proc/sys/kernel/unprivileged_userns_clone"
	if data, err := os.ReadFile(userNSFile); err == nil {
		if len(data) > 0 && strings.TrimSpace(string(data)) != "1" {
			return fmt.Errorf("user namespaces are disabled. Enable with: sudo sysctl -w kernel.unprivileged_userns_clone=1")
		}
	} else {
		logger.Warn("Could not check user namespace support", "error", err)
	}

	logger.Debug("Unprivileged mode validation passed")
	return nil
}

// getSlirp4netnsPath returns the path to slirp4netns for logging
func getSlirp4netnsPath() string {
	if path, err := exec.LookPath("slirp4netns"); err == nil {
		return path
	}
	return "not found"
}