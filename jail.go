package jail

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"time"
)

type Commander interface {
	Open() error
	SetEnv(key string, value string)
	Command(command []string) *exec.Cmd
	Close() error
}

type ProxyServer interface {
	Start(ctx context.Context) error
	Stop() error
}

type Config struct {
	Commander   Commander
	ProxyServer ProxyServer
	Logger      *slog.Logger
}

type Jail struct {
	commandExecutor Commander
	proxyServer     ProxyServer
	logger          *slog.Logger
	cancel          context.CancelFunc
	ctx             context.Context
}

func New(config Config) *Jail {
	ctx, cancel := context.WithCancel(context.Background())

	return &Jail{
		commandExecutor: config.Commander,
		proxyServer:     config.ProxyServer,
		logger:          config.Logger,
		ctx:             ctx,
		cancel:          cancel,
	}
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
