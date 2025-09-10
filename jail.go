package jail

import (
	"context"
	cryptotls "crypto/tls"
	"fmt"
	"log/slog"
	"os/exec"
	"time"

	"github.com/coder/jail/audit"
	"github.com/coder/jail/proxy"
	"github.com/coder/jail/rules"
	"github.com/coder/jail/tls"
)

type Commander interface {
	Open() error
	Command(command []string) *exec.Cmd
	Close() error
}

type Config struct {
	CommandExecutor Commander
	AllowRules      []string
	NoTLSIntercept  bool
	Logger          *slog.Logger
	ConfigDir       string
	HTTPPort        int
	HTTPSPort       int
}

type Jail struct {
	commandExecutor Commander
	proxyServer     *proxy.ProxyServer
	certManager     *tls.CertificateManager
	ruleEngine      *rules.RuleEngine
	auditor         *audit.LoggingAuditor
	logger          *slog.Logger
	cancel          context.CancelFunc
	ctx             context.Context
}

func New(config Config) (*Jail, error) {
	// Parse allow rules
	allowRules, err := rules.ParseAllowSpecs(config.AllowRules)
	if err != nil {
		config.Logger.Error("Failed to parse allow rules", "error", err)
		return nil, fmt.Errorf("failed to parse allow rules: %v", err)
	}

	// Create rule engine
	ruleEngine := rules.NewRuleEngine(allowRules, config.Logger)

	// Create auditor
	auditor := audit.NewLoggingAuditor(config.Logger)

	// Create certificate manager (if TLS interception is enabled)
	var certManager *tls.CertificateManager
	var tlsConfig *cryptotls.Config

	if !config.NoTLSIntercept {
		certManager, err = tls.NewCertificateManager(config.ConfigDir, config.Logger)
		if err != nil {
			config.Logger.Error("Failed to create certificate manager", "error", err)
			return nil, fmt.Errorf("failed to create certificate manager: %v", err)
		}
		tlsConfig = certManager.GetTLSConfig()
	}

	// Create proxy server
	proxyConfig := proxy.Config{
		HTTPPort:   config.HTTPPort,
		HTTPSPort:  config.HTTPSPort,
		RuleEngine: ruleEngine,
		Auditor:    auditor,
		Logger:     config.Logger,
		TLSConfig:  tlsConfig,
	}

	proxyServer := proxy.NewProxyServer(proxyConfig)

	ctx, cancel := context.WithCancel(context.Background())

	return &Jail{
		commandExecutor: config.CommandExecutor,
		proxyServer:     proxyServer,
		certManager:     certManager,
		ruleEngine:      ruleEngine,
		auditor:         auditor,
		logger:          config.Logger,
		ctx:             ctx,
		cancel:          cancel,
	}, nil
}

func (j *Jail) Open() error {
	// Open the command executor (network namespace)
	err := j.commandExecutor.Open()
	if err != nil {
		return fmt.Errorf("failed to open command executor: %v", err)
	}

	// Start proxy server in background
	go func() {
		err := j.proxyServer.Start(j.ctx)
		if err != nil {
			j.logger.Error("Proxy server error", "error", err)
		}
	}()

	// Give proxy time to start
	time.Sleep(100 * time.Millisecond)

	return nil
}

func (j *Jail) Command(command []string) *exec.Cmd {
	return j.commandExecutor.Command(command)
}

func (j *Jail) GetCACertPEM() ([]byte, error) {
	if j.certManager == nil {
		return nil, fmt.Errorf("certificate manager not available (TLS interception disabled)")
	}
	return j.certManager.GetCACertPEM()
}

func (j *Jail) Close() error {
	// Cancel context to stop proxy server
	if j.cancel != nil {
		j.cancel()
	}

	// Stop proxy server
	if j.proxyServer != nil {
		err := j.proxyServer.Stop()
		if err != nil {
			j.logger.Error("Failed to stop proxy server", "error", err)
		}
	}

	// Close command executor
	return j.commandExecutor.Close()
}