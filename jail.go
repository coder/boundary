package jail

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"runtime"
	"time"

	"github.com/coder/jail/audit"
	"github.com/coder/jail/namespace"
	"github.com/coder/jail/proxy"
	"github.com/coder/jail/rules"
	"github.com/coder/jail/tls"
)

type Config struct {
	RuleEngine   rules.Evaluator
	Auditor      audit.Auditor
	CertManager  tls.Manager
	Logger       *slog.Logger
	UserInfo     namespace.UserInfo
	Unprivileged bool
}

type Jail struct {
	commander   namespace.Commander
	proxyServer *proxy.Server
	logger      *slog.Logger
	ctx         context.Context
	cancel      context.CancelFunc
}

func New(ctx context.Context, config Config) (*Jail, error) {
	// Setup TLS config and write CA certificate to file
	tlsConfig, caCertPath, configDir, err := config.CertManager.SetupTLSAndWriteCACert()
	if err != nil {
		return nil, fmt.Errorf("failed to setup TLS and CA certificate: %v", err)
	}

	// Create proxy server
	proxyServer := proxy.NewProxyServer(proxy.Config{
		HTTPPort:   8080,
		RuleEngine: config.RuleEngine,
		Auditor:    config.Auditor,
		Logger:     config.Logger,
		TLSConfig:  tlsConfig,
	})

	// Create namespace
	commander, err := newNamespaceCommander(namespace.Config{
		Logger:        config.Logger,
		HttpProxyPort: 8080,
		TlsConfigDir:  configDir,
		CACertPath:    caCertPath,
		UserInfo:      config.UserInfo,
	}, config.Unprivileged)
	if err != nil {
		return nil, fmt.Errorf("failed to create namespace commander: %v", err)
	}

	// Create cancellable context for jail
	ctx, cancel := context.WithCancel(ctx)

	return &Jail{
		commander:   commander,
		proxyServer: proxyServer,
		logger:      config.Logger,
		ctx:         ctx,
		cancel:      cancel,
	}, nil
}

func (j *Jail) Start() error {
	// Open the command executor (network namespace)
	err := j.commander.Start()
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
	return j.commander.Command(command)
}

func (j *Jail) Close() error {
	// Stop proxy server
	if j.proxyServer != nil {
		err := j.proxyServer.Stop()
		if err != nil {
			j.logger.Error("Failed to stop proxy server", "error", err)
		}
	}

	// Close command executor
	return j.commander.Close()
}

// newNamespaceCommander creates a new namespace instance for the current platform
func newNamespaceCommander(config namespace.Config, unprivledged bool) (namespace.Commander, error) {
	if unprivledged {
		return namespace.NewUnprivileged(config)
	}

	switch runtime.GOOS {
	case "darwin":
		return namespace.NewMacOS(config)
	case "linux":
		return namespace.NewLinux(config)
	default:
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}
