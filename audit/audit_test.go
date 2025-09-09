package audit

import (
	"log/slog"
	"net/http"
	"testing"

	"github.com/coder/jail/rules"
)

func TestLoggingAuditor(t *testing.T) {
	// Create a logger that discards output during tests
	logger := slog.New(slog.NewTextHandler(nil, &slog.HandlerOptions{
		Level: slog.LevelError + 1, // Higher than any level to suppress all logs
	}))

	auditor := NewLoggingAuditor(logger)

	tests := []struct {
		name    string
		request *Request
	}{
		{
			name: "allow request",
			request: &Request{
				Method: "GET",
				URL:    "https://github.com",
				Action: rules.Allow,
				Rule:   "allow github.com",
			},
		},
		{
			name: "deny request",
			request: &Request{
				Method: "POST",
				URL:    "https://example.com",
				Action: rules.Deny,
				Reason: "no matching allow rules",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			auditor.AuditRequest(tt.request)
		})
	}
}

func TestHTTPRequestToAuditRequest(t *testing.T) {
	req, err := http.NewRequest("GET", "https://example.com/path?query=value", nil)
	if err != nil {
		t.Fatalf("failed to create HTTP request: %v", err)
	}

	auditReq := HTTPRequestToAuditRequest(req)

	if auditReq.Method != "GET" {
		t.Errorf("expected method GET, got %s", auditReq.Method)
	}

	expectedURL := "https://example.com/path?query=value"
	if auditReq.URL != expectedURL {
		t.Errorf("expected URL %s, got %s", expectedURL, auditReq.URL)
	}
}