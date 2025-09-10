package cli

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/coder/jail"
	"github.com/coder/serpent"
)

// Config holds all configuration for the CLI
type Config struct {
	AllowStrings   []string
	NoTLSIntercept bool
	LogLevel       string
	NoJailCleanup  bool
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
				Flag:        "allow",
				Description: "Allow rule (repeatable). Format: \"pattern\" or \"METHOD[,METHOD] pattern\"",
				Value:       serpent.StringArrayOf(&config.AllowStrings),
			},
			{
				Flag:        "log-level",
				Description: "Set log level (error, warn, info, debug)",
				Default:     "warn",
				Value:       serpent.StringOf(&config.LogLevel),
			},
			{
				Flag:        "no-tls-intercept",
				Description: "Disable HTTPS interception",
				Value:       serpent.BoolOf(&config.NoTLSIntercept),
			},
			{
				Flag:        "no-jail-cleanup",
				Description: "Disable jail cleanup (for debugging)",
				Value:       serpent.BoolOf(&config.NoJailCleanup),
				Hidden:      true,
			},
		},
		Handler: func(inv *serpent.Invocation) error {
			return Run(config, inv.Args)
		},
	}
}

// Run executes the jail with the given configuration and command arguments
func Run(config Config, args []string) error {
	logger := setupLogging(config.LogLevel)

	// Get command arguments
	if len(args) == 0 {
		return fmt.Errorf("no command specified")
	}

	// Warn if no allow rules specified
	if len(config.AllowStrings) == 0 {
		logger.Warn("No allow rules specified; all network traffic will be denied by default")
	}

	// Create jail configuration
	jailConfig := jail.Config{
		AllowRules:     config.AllowStrings,
		NoTLSIntercept: config.NoTLSIntercept,
		Logger:         logger,
		SkipCleanup:    config.NoJailCleanup,
	}

	// Create jail instance
	j, err := jail.New(jailConfig)
	if err != nil {
		return fmt.Errorf("failed to create jail: %v", err)
	}

	// Run the command in the jail
	return j.Run(args, nil)
}

// setupLogging configures and returns a logger based on the log level
func setupLogging(level string) *slog.Logger {
	var slogLevel slog.Level
	switch level {
	case "debug":
		slogLevel = slog.LevelDebug
	case "info":
		slogLevel = slog.LevelInfo
	case "warn":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelWarn
	}

	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slogLevel,
	}))
}