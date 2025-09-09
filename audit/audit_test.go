package audit

import (
	"bytes"
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

func TestLoggingAuditor(t *testing.T) {
	tests := []struct {
		name           string
		request        *Request
		expectedLevel  string
		expectedFields []string
	}{
		{
			name: "allow request",
			request: &Request{
				Method:  "GET",
				URL:     "https://github.com",
				Allowed: true,
				Rule:    "allow github.com",
			},
			expectedLevel: "INFO",
			expectedFields: []string{"ALLOW", "GET", "https://github.com", "allow github.com"},
		},
		{
			name: "deny request",
			request: &Request{
				Method:  "POST",
				URL:     "https://example.com",
				Allowed: false,
				Reason:  ReasonNoMatchingRules,
			},
			expectedLevel: "WARN",
			expectedFields: []string{"DENY", "POST", "https://example.com", ReasonNoMatchingRules},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
				Level: slog.LevelDebug,
			}))

			auditor := NewLoggingAuditor(logger)
			auditor.AuditRequest(tt.request)

			logOutput := buf.String()
			if logOutput == "" {
				t.Fatalf("expected log output, got empty string")
			}

			if !strings.Contains(logOutput, tt.expectedLevel) {
				t.Errorf("expected log level %s, got: %s", tt.expectedLevel, logOutput)
			}

			for _, field := range tt.expectedFields {
				if !strings.Contains(logOutput, field) {
					t.Errorf("expected log to contain %q, got: %s", field, logOutput)
				}
			}
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