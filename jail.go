package jail

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os/exec"
	"time"

	"github.com/coder/jail/proxy"
	"github.com/coder/jail/rules"
)

type Commander interface {
	Start(httpProxyPort int, httpsProxyPort int) error
	SetEnv(key string, value string)
	Command(command []string) *exec.Cmd
	Close() error
}

type Config struct {
	Commander  Commander
	RuleEngine *rules.RuleEngine
	Logger     *slog.Logger
	TLSConfig  *tls.Config
}

type Jail struct {
	commandExecutor Commander
	proxyServer     *proxy.ProxyServer
	logger          *slog.Logger
	ctx             context.Context
	cancel          context.CancelFunc
}

func New(config Config) *Jail {
	ctx, cancel := context.WithCancel(context.Background())

	return &Jail{
		commandExecutor: config.Commander,
		proxyServer: proxy.NewProxyServer(proxy.Config{
			HTTPPort:   8080,
			HTTPSPort:  8443,
			RuleEngine: config.RuleEngine,
			Logger:     config.Logger,
			TLSConfig:  config.TLSConfig,
		}),
		logger: config.Logger,
		ctx:    ctx,
		cancel: cancel,
	}
}

func (j *Jail) Start() error {
	// Open the command executor (network namespace)
	err := j.commandExecutor.Start(8080, 8443)
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

func (j *Jail) Close() error {
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
