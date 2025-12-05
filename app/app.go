package app

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/coder/serpent"
)

// Config holds all configuration for the CLI
type Config struct {
	Config                           serpent.YAMLConfigPath `yaml:"-"`
	AllowListStrings                 serpent.StringArray    `yaml:"allowlist"` // From config file
	AllowStrings                     serpent.StringArray    `yaml:"-"`         // From CLI flags only
	LogLevel                         serpent.String         `yaml:"log_level"`
	LogDir                           serpent.String         `yaml:"log_dir"`
	ProxyPort                        serpent.Int64          `yaml:"proxy_port"`
	PprofEnabled                     serpent.Bool           `yaml:"pprof_enabled"`
	PprofPort                        serpent.Int64          `yaml:"pprof_port"`
	ConfigureDNSForLocalStubResolver serpent.Bool           `yaml:"configure_dns_for_local_stub_resolver"`
}

func isChild() bool {
	return os.Getenv("CHILD") == "true"
}

// Run executes the boundary command with the given configuration and arguments
func Run(ctx context.Context, config Config, args []string) error {
	logger, err := setupLogging(config)
	if err != nil {
		return fmt.Errorf("could not set up logging: %v", err)
	}

	configInJSON, err := json.Marshal(config)
	if err != nil {
		return err
	}
	logger.Debug("config", "json_config", configInJSON)

	if isChild() {
		return RunChild(logger, args)
	}

	return RunParent(ctx, logger, args, config)
}

// setupLogging creates a slog logger with the specified level
func setupLogging(config Config) (*slog.Logger, error) {
	var level slog.Level
	switch strings.ToLower(config.LogLevel.Value()) {
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

	logTarget := os.Stderr

	logDir := config.LogDir.Value()
	if logDir != "" {
		// Set up the logging directory if it doesn't exist yet
		if err := os.MkdirAll(logDir, 0755); err != nil {
			return nil, fmt.Errorf("could not set up log dir %s: %v", logDir, err)
		}

		// Create a logfile (timestamp and pid to avoid race conditions with multiple boundary calls running)
		logFilePath := fmt.Sprintf("boundary-%s-%d.log",
			time.Now().Format("2006-01-02_15-04-05"),
			os.Getpid())

		logFile, err := os.Create(filepath.Join(logDir, logFilePath))
		if err != nil {
			return nil, fmt.Errorf("could not create log file %s: %v", logFilePath, err)
		}

		// Set the log target to the file rather than stderr.
		logTarget = logFile
	}

	// Create a standard slog logger with the appropriate level
	handler := slog.NewTextHandler(logTarget, &slog.HandlerOptions{
		Level: level,
	})

	return slog.New(handler), nil
}
