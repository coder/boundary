package audit

import "log/slog"

// LoggingAuditor implements proxy.Auditor by logging to slog
type LoggingAuditor struct {
	logger *slog.Logger
}

// NewLoggingAuditor creates a new LoggingAuditor
func NewLoggingAuditor(logger *slog.Logger) *LoggingAuditor {
	return &LoggingAuditor{
		logger: logger,
	}
}

// AuditRequest logs the request using structured logging
func (a *LoggingAuditor) AuditRequest(req Request) {
	if req.Allowed {
		a.logger.Info("ALLOW",
			"method", req.Method,
			"url", req.URL,
			"rule", req.Rule)
	} else {
		a.logger.Warn("DENY",
			"method", req.Method,
			"url", req.URL)
	}
}
