package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/coder/boundary"
	"github.com/coder/boundary/audit"
	"github.com/coder/boundary/jail"
	"github.com/coder/boundary/rulesengine"
	"github.com/coder/boundary/tls"
	"github.com/coder/boundary/util"
	"github.com/coder/serpent"
)

// Config holds all configuration for the CLI
type Config struct {
	Config          serpent.YAMLConfigPath `yaml:"-"`
	AllowListStrings serpent.StringArray   `yaml:"allowlist"` // From config file
	AllowStrings    serpent.StringArray    `yaml:"-"`       // From CLI flags only
	LogLevel        serpent.String         `yaml:"log_level"`
	LogDir          serpent.String         `yaml:"log_dir"`
	ProxyPort       serpent.Int64          `yaml:"proxy_port"`
	PprofEnabled    serpent.Bool           `yaml:"pprof_enabled"`
	PprofPort       serpent.Int64          `yaml:"pprof_port"`
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
  boundary --allow "domain=github.com" -- curl https://github.com

  # Monitor all requests to specific domains (allow only those)
  boundary --allow "domain=github.com path=/api/issues/*" --allow "method=GET,HEAD domain=github.com" -- npm install

  # Use allowlist from config file with additional CLI allow rules
  boundary --allow "domain=example.com" -- curl https://example.com

  # Block everything by default (implicit)`

	return cmd
}

// Base command returns the boundary serpent command without the information involved in making it the
// *top level* serpent command. We are creating this split to make it easier to integrate into the coder
// CLI if needed.
func BaseCommand() *serpent.Command {
	config := Config{}

	// Set default config path if file exists - serpent will load it automatically
	logToFile := func(message string) {
		if logFile, err := os.OpenFile("/tmp/yev_boundary_log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
			fmt.Fprintf(logFile, "[%s] %s\n", time.Now().Format(time.RFC3339), message)
			logFile.Close()
		}
	}

	if home, err := os.UserHomeDir(); err == nil {
		defaultPath := filepath.Join(home, ".config", "coder_boundary", "config.yaml")
		if _, err := os.Stat(defaultPath); err == nil {
			config.Config = serpent.YAMLConfigPath(defaultPath)
			logToFile(fmt.Sprintf("Config file loaded: %s", defaultPath))
		} else {
			logToFile(fmt.Sprintf("Config file not found: %s", defaultPath))
		}
	} else {
		logToFile("Failed to determine home directory, cannot check for default config")
	}

	return &serpent.Command{
		Use:   "boundary",
		Short: "Network isolation tool for monitoring and restricting HTTP/HTTPS requests",
		Long:  `boundary creates an isolated network environment for target processes, intercepting HTTP/HTTPS traffic through a transparent proxy that enforces user-defined allow rules.`,
		Options: []serpent.Option{
			{
				Flag:        "config",
				Env:         "BOUNDARY_CONFIG",
				Description: "Path to YAML config file.",
				Value:       &config.Config,
				YAML:        "",
			},
			{
				Flag:        "allow",
				Env:         "BOUNDARY_ALLOW",
				Description: "Allow rule (repeatable). These are merged with allowlist from config file. Format: \"pattern\" or \"METHOD[,METHOD] pattern\".",
				Value:       &config.AllowStrings,
				YAML:        "", // CLI only, not loaded from YAML
			},
			{
				Flag:        "", // No CLI flag, YAML only
				Description:  "Allowlist rules from config file (YAML only).",
				Value:        &config.AllowListStrings,
				YAML:         "allowlist",
			},
			{
				Flag:        "log-level",
				Env:         "BOUNDARY_LOG_LEVEL",
				Description: "Set log level (error, warn, info, debug).",
				Default:     "warn",
				Value:       &config.LogLevel,
				YAML:        "log_level",
			},
			{
				Flag:        "log-dir",
				Env:         "BOUNDARY_LOG_DIR",
				Description: "Set a directory to write logs to rather than stderr.",
				Value:       &config.LogDir,
				YAML:        "log_dir",
			},
			{
				Flag:        "proxy-port",
				Env:         "PROXY_PORT",
				Description: "Set a port for HTTP proxy.",
				Default:     "8080",
				Value:       &config.ProxyPort,
				YAML:        "proxy_port",
			},
			{
				Flag:        "pprof",
				Env:         "BOUNDARY_PPROF",
				Description: "Enable pprof profiling server.",
				Value:       &config.PprofEnabled,
				YAML:        "pprof_enabled",
			},
			{
				Flag:        "pprof-port",
				Env:         "BOUNDARY_PPROF_PORT",
				Description: "Set port for pprof profiling server.",
				Default:     "6060",
				Value:       &config.PprofPort,
				YAML:        "pprof_port",
			},
		},
		Handler: func(inv *serpent.Invocation) error {
			args := inv.Args
			return Run(inv.Context(), config, args)
		},
	}
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
		logger.Info("boundary CHILD process is started")

		vethNetJail := os.Getenv("VETH_JAIL_NAME")
		err := jail.SetupChildNetworking(vethNetJail)
		if err != nil {
			return fmt.Errorf("failed to setup child networking: %v", err)
		}
		logger.Info("child networking is successfully configured")

		// Program to run
		bin := args[0]
		args = args[1:]

		cmd := exec.Command(bin, args...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err = cmd.Run()
		if err != nil {
			log.Printf("failed to run %s: %v", bin, err)
			return err
		}

		return nil
	}

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
	jailer, err := createJailer(jail.Config{
		Logger:        logger,
		HttpProxyPort: int(config.ProxyPort.Value()),
		Username:      username,
		Uid:           uid,
		Gid:           gid,
		HomeDir:       homeDir,
		ConfigDir:     configDir,
		CACertPath:    caCertPath,
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

// createJailer creates a new jail instance for the current platform
func createJailer(config jail.Config) (jail.Jailer, error) {
	// Use the DefaultOS function for platform-specific jail creation
	return jail.DefaultOS(config)
}
