package audit

import "log/slog"

// LogAuditor implements proxy.Auditor by logging to slog
type LogAuditor struct {
	logger    *slog.Logger
	sessionID string
}

// NewLogAuditor creates a new LogAuditor
func NewLogAuditor(logger *slog.Logger) *LogAuditor {
	return &LogAuditor{
		logger: logger,
	}
}

// NewLogAuditorWithSession creates a new LogAuditor that includes a session ID on every log line.
func NewLogAuditorWithSession(logger *slog.Logger, sessionID string) *LogAuditor {
	return &LogAuditor{
		logger:    logger,
		sessionID: sessionID,
	}
}

// AuditRequest logs the request using structured logging
func (a *LogAuditor) AuditRequest(req Request) {
	fields := []any{
		"method", req.Method,
		"url", req.URL,
		"host", req.Host,
	}
	if a.sessionID != "" {
		fields = append(fields, "session_id", a.sessionID)
	}
	if req.Allowed {
		a.logger.Info("ALLOW", append(fields, "rule", req.Rule)...)
	} else {
		a.logger.Warn("DENY", fields...)
	}
}
