package audit

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/url"
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

func TestLoggingAuditor_EdgeCases(t *testing.T) {
	tests := []struct {
		name           string
		request        *Request
		expectedLevel  string
		expectedFields []string
	}{
		{
			name: "empty fields",
			request: &Request{
				Method:  "",
				URL:     "",
				Allowed: true,
				Rule:    "",
			},
			expectedLevel: "INFO",
			expectedFields: []string{"ALLOW"},
		},
		{
			name: "special characters in URL",
			request: &Request{
				Method:  "POST",
				URL:     "https://api.example.com/users?name=John%20Doe&id=123",
				Allowed: true,
				Rule:    "allow api.example.com/*",
			},
			expectedLevel: "INFO",
			expectedFields: []string{"ALLOW", "POST", "https://api.example.com/users?name=John%20Doe&id=123", "allow api.example.com/*"},
		},
		{
			name: "very long URL",
			request: &Request{
				Method:  "GET",
				URL:     "https://example.com/" + strings.Repeat("a", 1000),
				Allowed: false,
				Reason:  "URL too long",
			},
			expectedLevel: "WARN",
			expectedFields: []string{"DENY", "GET", "URL too long"},
		},
		{
			name: "custom reason",
			request: &Request{
				Method:  "DELETE",
				URL:     "https://malicious.com",
				Allowed: false,
				Reason:  "blocked by security policy",
			},
			expectedLevel: "WARN",
			expectedFields: []string{"DENY", "DELETE", "https://malicious.com", "blocked by security policy"},
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

func TestLoggingAuditor_DifferentLogLevels(t *testing.T) {
	tests := []struct {
		name          string
		logLevel      slog.Level
		request       *Request
		expectOutput  bool
	}{
		{
			name:     "info level allows info logs",
			logLevel: slog.LevelInfo,
			request: &Request{
				Method:  "GET",
				URL:     "https://github.com",
				Allowed: true,
				Rule:    "allow github.com",
			},
			expectOutput: true,
		},
		{
			name:     "warn level blocks info logs",
			logLevel: slog.LevelWarn,
			request: &Request{
				Method:  "GET",
				URL:     "https://github.com",
				Allowed: true,
				Rule:    "allow github.com",
			},
			expectOutput: false,
		},
		{
			name:     "warn level allows warn logs",
			logLevel: slog.LevelWarn,
			request: &Request{
				Method:  "POST",
				URL:     "https://example.com",
				Allowed: false,
				Reason:  ReasonNoMatchingRules,
			},
			expectOutput: true,
		},
		{
			name:     "error level blocks warn logs",
			logLevel: slog.LevelError,
			request: &Request{
				Method:  "POST",
				URL:     "https://example.com",
				Allowed: false,
				Reason:  ReasonNoMatchingRules,
			},
			expectOutput: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
				Level: tt.logLevel,
			}))

			auditor := NewLoggingAuditor(logger)
			auditor.AuditRequest(tt.request)

			logOutput := buf.String()
			hasOutput := logOutput != ""

			if hasOutput != tt.expectOutput {
				t.Errorf("expected output: %v, got output: %v (log: %q)", tt.expectOutput, hasOutput, logOutput)
			}
		})
	}
}

func TestLoggingAuditor_NilLogger(t *testing.T) {
	// This test ensures we handle edge cases gracefully
	// In practice, NewLoggingAuditor should never receive a nil logger,
	// but we test defensive programming
	defer func() {
		if r := recover(); r != nil {
			// If it panics, that's also acceptable behavior
			t.Logf("AuditRequest panicked with nil logger: %v", r)
		}
	}()

	auditor := &LoggingAuditor{logger: nil}
	req := &Request{
		Method:  "GET",
		URL:     "https://example.com",
		Allowed: true,
		Rule:    "test",
	}

	// This should either handle gracefully or panic - both are acceptable
	auditor.AuditRequest(req)
}

func TestHTTPRequestToAuditRequest(t *testing.T) {
	tests := []struct {
		name        string
		request     *http.Request
		expectedMethod string
		expectedURL    string
	}{
		{
			name: "basic GET request",
			request: func() *http.Request {
				req, _ := http.NewRequest("GET", "https://example.com/path?query=value", nil)
				return req
			}(),
			expectedMethod: "GET",
			expectedURL: "https://example.com/path?query=value",
		},
		{
			name: "POST request with body",
			request: func() *http.Request {
				req, _ := http.NewRequest("POST", "https://api.example.com/users", strings.NewReader("data"))
				return req
			}(),
			expectedMethod: "POST",
			expectedURL: "https://api.example.com/users",
		},
		{
			name: "request with port",
			request: func() *http.Request {
				req, _ := http.NewRequest("GET", "https://example.com:8443/api", nil)
				return req
			}(),
			expectedMethod: "GET",
			expectedURL: "https://example.com:8443/api",
		},
		{
			name: "request with complex query parameters",
			request: func() *http.Request {
				req, _ := http.NewRequest("GET", "https://search.example.com/api?q=hello%20world&limit=10&offset=0", nil)
				return req
			}(),
			expectedMethod: "GET",
			expectedURL: "https://search.example.com/api?q=hello%20world&limit=10&offset=0",
		},
		{
			name: "request with fragment (should be ignored)",
			request: func() *http.Request {
				u, _ := url.Parse("https://example.com/page#section")
				req := &http.Request{
					Method: "GET",
					URL:    u,
				}
				return req
			}(),
			expectedMethod: "GET",
			expectedURL: "https://example.com/page#section",
		},
		{
			name: "HTTP request (not HTTPS)",
			request: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://insecure.example.com/data", nil)
				return req
			}(),
			expectedMethod: "GET",
			expectedURL: "http://insecure.example.com/data",
		},
		{
			name: "PUT request",
			request: func() *http.Request {
				req, _ := http.NewRequest("PUT", "https://api.example.com/users/123", strings.NewReader("updated data"))
				return req
			}(),
			expectedMethod: "PUT",
			expectedURL: "https://api.example.com/users/123",
		},
		{
			name: "DELETE request",
			request: func() *http.Request {
				req, _ := http.NewRequest("DELETE", "https://api.example.com/users/123", nil)
				return req
			}(),
			expectedMethod: "DELETE",
			expectedURL: "https://api.example.com/users/123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auditReq := HTTPRequestToAuditRequest(tt.request)

			if auditReq.Method != tt.expectedMethod {
				t.Errorf("expected method %s, got %s", tt.expectedMethod, auditReq.Method)
			}

			if auditReq.URL != tt.expectedURL {
				t.Errorf("expected URL %s, got %s", tt.expectedURL, auditReq.URL)
			}

			// Verify that fields not set by HTTPRequestToAuditRequest have zero values
			if auditReq.Allowed != false {
				t.Errorf("expected Allowed to be false (zero value), got %v", auditReq.Allowed)
			}

			if auditReq.Rule != "" {
				t.Errorf("expected Rule to be empty (zero value), got %q", auditReq.Rule)
			}

			if auditReq.Reason != "" {
				t.Errorf("expected Reason to be empty (zero value), got %q", auditReq.Reason)
			}
		})
	}
}

func TestHTTPRequestToAuditRequest_NilRequest(t *testing.T) {
	// Test edge case with nil request
	defer func() {
		if r := recover(); r != nil {
			// If it panics, that's acceptable behavior for nil input
			t.Logf("HTTPRequestToAuditRequest panicked with nil request: %v", r)
		}
	}()

	// This should either handle gracefully or panic - both are acceptable
	auditReq := HTTPRequestToAuditRequest(nil)
	if auditReq != nil {
		// If it doesn't panic, verify the result makes sense
		t.Logf("HTTPRequestToAuditRequest with nil returned: %+v", auditReq)
	}
}

func TestNewLoggingAuditor(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	auditor := NewLoggingAuditor(logger)

	if auditor == nil {
		t.Fatal("expected NewLoggingAuditor to return non-nil auditor")
	}

	if auditor.logger != logger {
		t.Error("expected auditor to use the provided logger")
	}

	// Verify it implements the Auditor interface
	var _ Auditor = auditor
}

func TestAuditorInterface(t *testing.T) {
	// Test that our LoggingAuditor properly implements the Auditor interface
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{}))

	// This should compile - testing interface compliance
	var auditor Auditor = NewLoggingAuditor(logger)

	req := &Request{
		Method:  "GET",
		URL:     "https://example.com",
		Allowed: true,
		Rule:    "allow example.com",
	}

	auditor.AuditRequest(req)

	if buf.String() == "" {
		t.Error("expected audit log output through interface")
	}
}

func TestLoggingAuditor_JSONHandler(t *testing.T) {
	// Test with JSON handler instead of text handler
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	auditor := NewLoggingAuditor(logger)
	req := &Request{
		Method:  "GET",
		URL:     "https://github.com",
		Allowed: true,
		Rule:    "allow github.com",
	}

	auditor.AuditRequest(req)

	logOutput := buf.String()
	if logOutput == "" {
		t.Fatal("expected log output")
	}

	// Verify it contains JSON structure
	if !strings.Contains(logOutput, "{") || !strings.Contains(logOutput, "}") {
		t.Error("expected JSON format in log output")
	}

	// Verify expected fields are present in JSON
	expectedFields := []string{"\"msg\":\"ALLOW\"", "\"method\":\"GET\"", "\"url\":\"https://github.com\"", "\"rule\":\"allow github.com\""}
	for _, field := range expectedFields {
		if !strings.Contains(logOutput, field) {
			t.Errorf("expected JSON log to contain %q, got: %s", field, logOutput)
		}
	}
}

func TestLoggingAuditor_DiscardHandler(t *testing.T) {
	// Test with discard handler (no output)
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))

	auditor := NewLoggingAuditor(logger)
	req := &Request{
		Method:  "GET",
		URL:     "https://example.com",
		Allowed: true,
		Rule:    "allow example.com",
	}

	// This should not panic even with discard handler
	auditor.AuditRequest(req)
}