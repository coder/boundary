// Package jail provides a library for creating network-isolated environments
// that monitor and restrict HTTP/HTTPS requests from processes.
package jail

import (
	"context"
	cryptotls "crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/coder/jail/audit"
	"github.com/coder/jail/network"
	"github.com/coder/jail/proxy"
	"github.com/coder/jail/rules"
	"github.com/coder/jail/tls"
)

// Config holds all configuration for jail
type Config struct {
	// AllowRules specifies which HTTP requests are allowed.
	// Format: "pattern" or "METHOD[,METHOD] pattern"
	// Example: "github.com", "GET,POST api.github.com"
	AllowRules []string

	// NoTLSIntercept disables HTTPS interception.
	// When true, HTTPS traffic will be blocked instead of intercepted.
	NoTLSIntercept bool

	// Logger is used for all jail logging.
	// If nil, a default logger will be created.
	Logger *slog.Logger

	// HTTPPort is the port for HTTP proxy (default: 8040)
	HTTPPort int

	// HTTPSPort is the port for HTTPS proxy (default: 8043)
	HTTPSPort int

	// NetJailName is the name for the network namespace (default: "jail")
	NetJailName string

	// SkipCleanup disables automatic cleanup on exit (for debugging)
	SkipCleanup bool
}

// Jail represents a network isolation environment
type Jail struct {
	config          Config
	logger          *slog.Logger
	networkInstance network.Jail
	proxyServer     *proxy.ProxyServer
	ctx             context.Context
	cancel          context.CancelFunc
	cleanedUp       bool
	extraEnv        map[string]string
}

// New creates a new jail instance with the given configuration.
func New(config Config) (*Jail, error) {
	// Set defaults
	if config.HTTPPort == 0 {
		config.HTTPPort = 8040
	}
	if config.HTTPSPort == 0 {
		config.HTTPSPort = 8043
	}
	if config.NetJailName == "" {
		config.NetJailName = "jail"
	}

	// Create logger if not provided
	logger := config.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelWarn,
		}))
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Jail{
		config:   config,
		logger:   logger,
		ctx:      ctx,
		cancel:   cancel,
		extraEnv: make(map[string]string),
	}, nil
}

// Start initializes the jail environment.
func (j *Jail) Start() error {
	if j.cleanedUp {
		return fmt.Errorf("jail has been cleaned up and cannot be reused")
	}

	// Parse allow rules
	allowRules, err := rules.ParseAllowSpecs(j.config.AllowRules)
	if err != nil {
		j.logger.Error("Failed to parse allow rules", "error", err)
		return fmt.Errorf("failed to parse allow rules: %v", err)
	}

	// Create rule engine
	ruleEngine := rules.NewRuleEngine(allowRules, j.logger)

	// Setup TLS if enabled
	var certManager *tls.CertificateManager
	var tlsConfig *cryptotls.Config

	if !j.config.NoTLSIntercept {
		// Get configuration directory
		configDir, err := tls.GetConfigDir()
		if err != nil {
			j.logger.Error("Failed to get config directory", "error", err)
			return fmt.Errorf("failed to get config directory: %v", err)
		}

		certManager, err = tls.NewCertificateManager(configDir, j.logger)
		if err != nil {
			j.logger.Error("Failed to create certificate manager", "error", err)
			return fmt.Errorf("failed to create certificate manager: %v", err)
		}

		tlsConfig = certManager.GetTLSConfig()

		// Setup CA certificate environment variables
		caCertPEM, err := certManager.GetCACertPEM()
		if err != nil {
			j.logger.Error("Failed to get CA certificate", "error", err)
			return fmt.Errorf("failed to get CA certificate: %v", err)
		}

		caCertPath := filepath.Join(configDir, "ca-cert.pem")
		err = os.WriteFile(caCertPath, caCertPEM, 0644)
		if err != nil {
			j.logger.Error("Failed to write CA certificate file", "error", err)
			return fmt.Errorf("failed to write CA certificate file: %v", err)
		}

		// Set CA certificate environment variables
		j.extraEnv["SSL_CERT_FILE"] = caCertPath
		j.extraEnv["SSL_CERT_DIR"] = configDir
		j.extraEnv["CURL_CA_BUNDLE"] = caCertPath
		j.extraEnv["GIT_SSL_CAINFO"] = caCertPath
		j.extraEnv["REQUESTS_CA_BUNDLE"] = caCertPath
		j.extraEnv["NODE_EXTRA_CA_CERTS"] = caCertPath
		j.extraEnv["JAIL_CA_CERT"] = string(caCertPEM)
	}

	// Create network jail
	networkConfig := network.JailConfig{
		HTTPPort:    j.config.HTTPPort,
		HTTPSPort:   j.config.HTTPSPort,
		NetJailName: j.config.NetJailName,
		SkipCleanup: j.config.SkipCleanup,
	}

	networkInstance, err := network.NewJail(networkConfig, j.logger)
	if err != nil {
		j.logger.Error("Failed to create network jail", "error", err)
		return fmt.Errorf("failed to create network jail: %v", err)
	}
	j.networkInstance = networkInstance

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Handle signals in background
	go func() {
		sig := <-sigChan
		j.logger.Info("Received signal, shutting down jail...", "signal", sig)
		j.cancel()
	}()

	// Setup network jail
	err = j.networkInstance.Setup(j.config.HTTPPort, j.config.HTTPSPort)
	if err != nil {
		j.logger.Error("Failed to setup network jail", "error", err)
		return fmt.Errorf("failed to setup network jail: %v", err)
	}

	// Create and start proxy server
	auditor := audit.NewLoggingAuditor(j.logger)
	proxyConfig := proxy.Config{
		HTTPPort:   j.config.HTTPPort,
		HTTPSPort:  j.config.HTTPSPort,
		RuleEngine: ruleEngine,
		Auditor:    auditor,
		Logger:     j.logger,
		TLSConfig:  tlsConfig,
	}

	j.proxyServer = proxy.NewProxyServer(proxyConfig)

	// Start proxy server
	go func() {
		err := j.proxyServer.Start(j.ctx)
		if err != nil && j.ctx.Err() == nil {
			j.logger.Error("Proxy server error", "error", err)
			j.cancel()
		}
	}()

	// Give proxy time to start
	time.Sleep(100 * time.Millisecond)

	return nil
}

// Execute runs a command in the jail environment.
// The jail must be started with Start() before calling this method.
func (j *Jail) Execute(command []string, additionalEnv map[string]string) error {
	if j.networkInstance == nil {
		return fmt.Errorf("jail not started - call Start() first")
	}
	if j.cleanedUp {
		return fmt.Errorf("jail has been cleaned up and cannot be reused")
	}
	if len(command) == 0 {
		return fmt.Errorf("no command specified")
	}

	// Merge extra environment with additional environment
	finalEnv := make(map[string]string)
	for k, v := range j.extraEnv {
		finalEnv[k] = v
	}
	for k, v := range additionalEnv {
		finalEnv[k] = v
	}

	// Execute command in network jail
	go func() {
		defer j.cancel()
		err := j.networkInstance.Execute(command, finalEnv)
		if err != nil {
			j.logger.Error("Command execution failed", "error", err)
		}
	}()

	// Wait for command completion or signal
	<-j.ctx.Done()

	return nil
}

// Stop gracefully shuts down the jail and cleans up resources.
func (j *Jail) Stop() error {
	if j.cleanedUp {
		return nil // Already cleaned up
	}

	j.logger.Debug("Stopping jail...")

	// Cancel context
	j.cancel()

	// Stop proxy server
	if j.proxyServer != nil {
		err := j.proxyServer.Stop()
		if err != nil {
			j.logger.Error("Failed to stop proxy server", "error", err)
		}
	}

	// Cleanup network jail
	if j.networkInstance != nil {
		err := j.networkInstance.Cleanup()
		if err != nil {
			j.logger.Error("Failed to cleanup network jail", "error", err)
			return err
		}
	}

	j.cleanedUp = true
	j.logger.Debug("Jail stopped successfully")
	return nil
}