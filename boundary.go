package boundary

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os/exec"
	"time"

	"github.com/coder/boundary/audit"
	"github.com/coder/boundary/jail"
	"github.com/coder/boundary/proxy"
	"github.com/coder/boundary/rulesengine"
)

type Config struct {
	RuleEngine rulesengine.Engine
	Auditor    audit.Auditor
	TLSConfig  *tls.Config
	Logger     *slog.Logger
	Jailer     jail.Jailer
}

type Boundary struct {
	config      Config
	jailer      jail.Jailer
	proxyServer *proxy.Server
	logger      *slog.Logger
	ctx         context.Context
	cancel      context.CancelFunc
}

func New(ctx context.Context, config Config) (*Boundary, error) {
	// Create proxy server
	proxyServer := proxy.NewProxyServer(proxy.Config{
		HTTPPort:   8080,
		RuleEngine: config.RuleEngine,
		Auditor:    config.Auditor,
		Logger:     config.Logger,
		TLSConfig:  config.TLSConfig,
	})

	// Create cancellable context for boundary
	ctx, cancel := context.WithCancel(ctx)

	return &Boundary{
		config:      config,
		jailer:      config.Jailer,
		proxyServer: proxyServer,
		logger:      config.Logger,
		ctx:         ctx,
		cancel:      cancel,
	}, nil
}

func (b *Boundary) Start() error {
	// Start the jailer (network isolation)
	err := b.jailer.Start()
	if err != nil {
		return fmt.Errorf("failed to start jailer: %v", err)
	}

	// Start proxy server in background
	err = b.proxyServer.Start()
	if err != nil {
		b.logger.Error("Proxy server error", "error", err)
		return err
	}

	// Give proxy time to start
	time.Sleep(100 * time.Millisecond)

	return nil
}

func (b *Boundary) Command(command []string) *exec.Cmd {
	return b.jailer.Command(command)
}

func (b *Boundary) Close() error {
	// Stop proxy server
	if b.proxyServer != nil {
		err := b.proxyServer.Stop()
		if err != nil {
			b.logger.Error("Failed to stop proxy server", "error", err)
		}
	}

	// Close jailer
	return b.jailer.Close()
}
