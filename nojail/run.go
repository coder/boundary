package nojail

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/coder/boundary/audit"
	"github.com/coder/boundary/config"
	"github.com/coder/boundary/proxy"
	"github.com/coder/boundary/rulesengine"
	tlspkg "github.com/coder/boundary/tls"
)

// Run executes the target command with the proxy and audit logging enabled,
// but without any jailing or network isolation. This is useful for testing
// the audit logging functionality on non-Linux platforms or when jailing
// is not desired.
func Run(ctx context.Context, logger *slog.Logger, cfg config.AppConfig) error {
	if len(cfg.AllowRules) == 0 {
		logger.Warn("No allow rules specified; all network traffic will be denied by default")
	}

	// Parse allow rules
	allowRules, err := rulesengine.ParseAllowSpecs(cfg.AllowRules)
	if err != nil {
		logger.Error("Failed to parse allow rules", "error", err)
		return fmt.Errorf("failed to parse allow rules: %v", err)
	}

	// Create rule engine
	ruleEngine := rulesengine.NewRuleEngine(allowRules, logger)

	// Create auditors
	stderrAuditor := audit.NewLogAuditor(logger)
	auditors := []audit.Auditor{stderrAuditor}
	if !cfg.DisableAuditLogs {
		socketAuditor := audit.NewSocketAuditor(logger)
		go socketAuditor.Loop(ctx)
		auditors = append(auditors, socketAuditor)
	}
	auditor := audit.NewMultiAuditor(auditors...)

	// Create TLS certificate manager
	certManager, err := tlspkg.NewCertificateManager(tlspkg.Config{
		Logger:    logger,
		ConfigDir: cfg.UserInfo.ConfigDir,
		Uid:       cfg.UserInfo.Uid,
		Gid:       cfg.UserInfo.Gid,
	})
	if err != nil {
		logger.Error("Failed to create certificate manager", "error", err)
		return fmt.Errorf("failed to create certificate manager: %v", err)
	}

	// Setup TLS to get cert path
	tlsConfig, err := certManager.SetupTLSAndWriteCACert()
	if err != nil {
		return fmt.Errorf("failed to setup TLS and CA certificate: %v", err)
	}

	runner := &noJailRunner{
		logger:    logger,
		config:    cfg,
		tlsConfig: tlsConfig,
		auditor:   auditor,
		engine:    ruleEngine,
	}

	return runner.Run(ctx)
}

type noJailRunner struct {
	proxyServer *proxy.Server
	logger      *slog.Logger
	config      config.AppConfig
	tlsConfig   *tls.Config
	auditor     audit.Auditor
	engine      rulesengine.Engine
}

func (r *noJailRunner) Run(ctx context.Context) error {
	r.logger.Info("Starting nojail runner (no network isolation)")

	// Create and start proxy server
	r.proxyServer = proxy.NewProxyServer(proxy.Config{
		HTTPPort:     int(r.config.ProxyPort),
		RuleEngine:   r.engine,
		Auditor:      r.auditor,
		Logger:       r.logger,
		TLSConfig:    r.tlsConfig,
		PprofEnabled: r.config.PprofEnabled,
		PprofPort:    int(r.config.PprofPort),
	})

	err := r.proxyServer.Start()
	if err != nil {
		return fmt.Errorf("failed to start proxy server: %v", err)
	}

	defer func() {
		r.logger.Info("Stopping nojail runner")
		if r.proxyServer != nil {
			if err := r.proxyServer.Stop(); err != nil {
				r.logger.Error("Failed to stop proxy server", "error", err)
			}
		}
	}()

	// Give proxy time to start
	time.Sleep(100 * time.Millisecond)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Run the child process
	go func() {
		defer cancel()
		err := r.runChildProcess()
		if err != nil {
			r.logger.Error("Failed to run child process", "error", err)
		}
	}()

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for signal or context cancellation
	select {
	case sig := <-sigChan:
		r.logger.Info("Received signal, shutting down...", "signal", sig)
		cancel()
	case <-ctx.Done():
		r.logger.Info("Command completed, shutting down...")
	}

	return nil
}

func (r *noJailRunner) runChildProcess() error {
	if len(r.config.TargetCMD) == 0 {
		return fmt.Errorf("no command specified")
	}

	cmd := exec.Command(r.config.TargetCMD[0], r.config.TargetCMD[1:]...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin

	// Set proxy environment variables so the child process uses our proxy
	proxyURL := fmt.Sprintf("http://127.0.0.1:%d", r.config.ProxyPort)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("HTTP_PROXY=%s", proxyURL),
		fmt.Sprintf("HTTPS_PROXY=%s", proxyURL),
		fmt.Sprintf("http_proxy=%s", proxyURL),
		fmt.Sprintf("https_proxy=%s", proxyURL),
	)

	r.logger.Debug("Executing command without jailing", "command", strings.Join(r.config.TargetCMD, " "))
	err := cmd.Start()
	if err != nil {
		r.logger.Error("Command failed to start", "error", err)
		return err
	}

	r.logger.Debug("Waiting for child process to finish")
	err = cmd.Wait()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode := exitError.ExitCode()
			r.logger.Debug("Command exited with non-zero status", "exit_code", exitCode)
			return err
		}
		r.logger.Error("Command execution failed", "error", err)
		return err
	}
	r.logger.Debug("Command completed successfully")

	return nil
}
