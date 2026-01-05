package landjail

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/coder/boundary/audit"
	"github.com/coder/boundary/config"
	"github.com/coder/boundary/rulesengine"
	"github.com/coder/boundary/tls"
)

func RunParent(ctx context.Context, logger *slog.Logger, config config.AppConfig) error {
	if len(config.AllowRules) == 0 {
		logger.Warn("No allow rules specified; all network traffic will be denied by default")
	}

	// Parse allow rules
	allowRules, err := rulesengine.ParseAllowSpecs(config.AllowRules)
	if err != nil {
		logger.Error("Failed to parse allow rules", "error", err)
		return fmt.Errorf("failed to parse allow rules: %v", err)
	}

	// Create rule engine
	ruleEngine := rulesengine.NewRuleEngine(allowRules, logger)

	// Create auditors
	stderrAuditor := audit.NewLogAuditor(logger)
	auditors := []audit.Auditor{stderrAuditor}
	if !config.DisableAuditLogs {
		if config.LogProxySocketPath == "" {
			return fmt.Errorf("log proxy socket path is undefined")
		}
		// Since boundary is separately versioned from a Coder deployment, it's possible
		// Coder is on an older version that will not create the socket and listen for
		// the audit logs. Here we check for the socket to determine if the workspace
		// agent is on a new enough version to prevent boundary application log spam from
		// trying to connect to the agent. This assumes the agent will run and start the
		// log proxy server before boundary runs.
		_, err := os.Stat(config.LogProxySocketPath)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to stat log proxy socket: %v", err)
		}
		agentWillProxy := !os.IsNotExist(err)
		if agentWillProxy {
			socketAuditor := audit.NewSocketAuditor(logger, config.LogProxySocketPath)
			go socketAuditor.Loop(ctx)
			auditors = append(auditors, socketAuditor)
		} else {
			logger.Warn("Audit logs are disabled; workspace agent has not created log proxy socket",
				"socket", config.LogProxySocketPath)
		}
	} else {
		logger.Warn("Audit logs are disabled by configuration")
	}
	auditor := audit.NewMultiAuditor(auditors...)

	// Create TLS certificate manager
	certManager, err := tls.NewCertificateManager(tls.Config{
		Logger:    logger,
		ConfigDir: config.UserInfo.ConfigDir,
		Uid:       config.UserInfo.Uid,
		Gid:       config.UserInfo.Gid,
	})
	if err != nil {
		logger.Error("Failed to create certificate manager", "error", err)
		return fmt.Errorf("failed to create certificate manager: %v", err)
	}

	// Setup TLS to get cert path for jailer
	tlsConfig, err := certManager.SetupTLSAndWriteCACert()
	if err != nil {
		return fmt.Errorf("failed to setup TLS and CA certificate: %v", err)
	}

	landjail, err := NewLandJail(ruleEngine, auditor, tlsConfig, logger, config)
	if err != nil {
		return fmt.Errorf("failed to create landjail: %v", err)
	}

	return landjail.Run(ctx)
}
