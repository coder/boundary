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
	Unprivileged bool // Enable unprivileged mode (user namespace + iptables)
}

type Jail struct {
	commander   namespace.Commander
	proxyServer *proxy.Server
	logger      *slog.Logger
	ctx         context.Context
	cancel      context.CancelFunc
}

func New(ctx context.Context, config Config) (*Jail, error) {
	// Validate unprivileged mode if requested
	if config.Unprivileged && runtime.GOOS != "linux" {
		return nil, fmt.Errorf("unprivileged mode only supports Linux, got: %s", runtime.GOOS)
	}

	// Setup TLS config and write CA certificate to file
	tlsConfig, caCertPath, configDir, err := config.CertManager.SetupTLSAndWriteCACert()
	if err != nil {
		return nil, fmt.Errorf("failed to setup TLS and CA certificate: %v", err)
	}

	// Create proxy server
	proxyServer := proxy.NewProxyServer(proxy.Config{
		HTTPPort:   8080,
		HTTPSPort:  8443,
		Auditor:    config.Auditor,
		RuleEngine: config.RuleEngine,
		Logger:     config.Logger,
		TLSConfig:  tlsConfig,
	})

	// Create commander
	commander, err := newNamespaceCommander(namespace.Config{
		Logger:         config.Logger,
		HttpProxyPort:  8080,
		HttpsProxyPort: 8443,
		Env: map[string]string{
			// Set standard CA certificate environment variables for common tools
			// This makes tools like curl, git, etc. trust our dynamically generated CA
			"SSL_CERT_FILE":       caCertPath, // OpenSSL/LibreSSL-based tools
			"SSL_CERT_DIR":        configDir,  // OpenSSL certificate directory
			"CURL_CA_BUNDLE":      caCertPath, // curl
			"GIT_SSL_CAINFO":      caCertPath, // Git
			"REQUESTS_CA_BUNDLE":  caCertPath, // Python requests
			"NODE_EXTRA_CA_CERTS": caCertPath, // Node.js
		},
	}, config.Unprivileged)
	if err != nil {
		return nil, fmt.Errorf("failed to create commander: %v", err)
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
func newNamespaceCommander(config namespace.Config, unprivileged bool) (namespace.Commander, error) {
	switch runtime.GOOS {
	case "darwin":
		if unprivileged {
			return nil, fmt.Errorf("unprivileged mode not available on macOS")
		}
		return namespace.NewMacOS(config)
	case "linux":
		if unprivileged {
			return namespace.NewUserNamespaceLinux(config)
		} else {
			return namespace.NewLinux(config)
		}
	default:
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}