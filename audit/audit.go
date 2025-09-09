package audit

import (
	"log/slog"
	"net/http"
)

// Request represents information about an HTTP request for auditing
type Request struct {
	Method  string
	URL     string
	Allowed bool
	Rule    string // The rule that matched (if any)
	Reason  string // Reason for the action (e.g., "no matching allow rules")
}

// Auditor handles audit logging for HTTP requests
type Auditor interface {
	// AuditRequest logs information about an HTTP request and the action taken
	AuditRequest(req *Request)
}

// LoggingAuditor implements Auditor by logging to slog
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
func (a *LoggingAuditor) AuditRequest(req *Request) {
	if req.Allowed {
		a.logger.Info("ALLOW", 
			"method", req.Method, 
			"url", req.URL, 
			"rule", req.Rule)
	} else {
		a.logger.Warn("DENY", 
			"method", req.Method, 
			"url", req.URL, 
			"reason", req.Reason)
	}
}

// HTTPRequestToAuditRequest converts an http.Request to an audit.Request
func HTTPRequestToAuditRequest(httpReq *http.Request) *Request {
	return &Request{
		Method: httpReq.Method,
		URL:    httpReq.URL.String(),
	}
}