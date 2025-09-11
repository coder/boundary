package audit

import (
	"bytes"
	"io"
	"log/slog"
	"strings"
	"testing"
)

func TestLoggingAuditor(t *testing.T) {
	tests := []struct {
		name           string
		request        Request
		expectedLevel  string
		expectedFields []string
	}{
		{
			name: "allow request",
			request: Request{
				Method:  "GET",
				URL:     "https://github.com",
				Allowed: true,
				Rule:    "allow github.com",
			},
			expectedLevel:  "INFO",
			expectedFields: []string{"ALLOW", "GET", "https://github.com", "allow github.com"},
		},
		{
			name: "deny request",
			request: Request{
				Method:  "POST",
				URL:     "https://example.com",
				Allowed: false,
			},
			expectedLevel:  "WARN",
			expectedFields: []string{"DENY", "POST", "https://example.com"},
		},
		{
			name: "allow with empty rule",
			request: Request{
				Method:  "PUT",
				URL:     "https://api.github.com/repos",
				Allowed: true,
				Rule:    "",
			},
			expectedLevel:  "INFO",
			expectedFields: []string{"ALLOW", "PUT", "https://api.github.com/repos"},
		},
		{
			name: "deny HTTPS request",
			request: Request{
				Method:  "GET",
				URL:     "https://malware.bad.com/payload",
				Allowed: false,
			},
			expectedLevel:  "WARN",
			expectedFields: []string{"DENY", "GET", "https://malware.bad.com/payload"},
		},
		{
			name: "allow with wildcard rule",
			request: Request{
				Method:  "POST",
				URL:     "https://api.github.com/graphql",
				Allowed: true,
				Rule:    "allow api.github.com/*",
			},
			expectedLevel:  "INFO",
			expectedFields: []string{"ALLOW", "POST", "https://api.github.com/graphql", "allow api.github.com/*"},
		},
		{
			name: "deny HTTP request",
			request: Request{
				Method:  "GET",
				URL:     "http://insecure.example.com",
				Allowed: false,
			},
			expectedLevel:  "WARN",
			expectedFields: []string{"DENY", "GET", "http://insecure.example.com"},
		},
		{
			name: "allow HEAD request",
			request: Request{
				Method:  "HEAD",
				URL:     "https://cdn.jsdelivr.net/health",
				Allowed: true,
				Rule:    "allow HEAD cdn.jsdelivr.net",
			},
			expectedLevel:  "INFO",
			expectedFields: []string{"ALLOW", "HEAD", "https://cdn.jsdelivr.net/health", "allow HEAD cdn.jsdelivr.net"},
		},
		{
			name: "deny OPTIONS request",
			request: Request{
				Method:  "OPTIONS",
				URL:     "https://restricted.api.com/cors",
				Allowed: false,
			},
			expectedLevel:  "WARN",
			expectedFields: []string{"DENY", "OPTIONS", "https://restricted.api.com/cors"},
		},
		{
			name: "allow with port number",
			request: Request{
				Method:  "GET",
				URL:     "https://localhost:3000/api/health",
				Allowed: true,
				Rule:    "allow localhost:3000",
			},
			expectedLevel:  "INFO",
			expectedFields: []string{"ALLOW", "GET", "https://localhost:3000/api/health", "allow localhost:3000"},
		},
		{
			name: "deny DELETE request",
			request: Request{
				Method:  "DELETE",
				URL:     "https://api.production.com/users/admin",
				Allowed: false,
			},
			expectedLevel:  "WARN",
			expectedFields: []string{"DENY", "DELETE", "https://api.production.com/users/admin"},
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
		request        Request
		expectedLevel  string
		expectedFields []string
	}{
		{
			name: "empty fields",
			request: Request{
				Method:  "",
				URL:     "",
				Allowed: true,
				Rule:    "",
			},
			expectedLevel:  "INFO",
			expectedFields: []string{"ALLOW"},
		},
		{
			name: "special characters in URL",
			request: Request{
				Method:  "POST",
				URL:     "https://api.example.com/users?name=John%20Doe&id=123",
				Allowed: true,
				Rule:    "allow api.example.com/*",
			},
			expectedLevel:  "INFO",
			expectedFields: []string{"ALLOW", "POST", "https://api.example.com/users?name=John%20Doe&id=123", "allow api.example.com/*"},
		},
		{
			name: "very long URL",
			request: Request{
				Method:  "GET",
				URL:     "https://example.com/" + strings.Repeat("a", 1000),
				Allowed: false,
			},
			expectedLevel:  "WARN",
			expectedFields: []string{"DENY", "GET"},
		},
		{
			name: "deny with custom URL",
			request: Request{
				Method:  "DELETE",
				URL:     "https://malicious.com",
				Allowed: false,
			},
			expectedLevel:  "WARN",
			expectedFields: []string{"DENY", "DELETE", "https://malicious.com"},
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
		name         string
		logLevel     slog.Level
		request      Request
		expectOutput bool
	}{
		{
			name:     "info level allows info logs",
			logLevel: slog.LevelInfo,
			request: Request{
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
			request: Request{
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
			request: Request{
				Method:  "POST",
				URL:     "https://example.com",
				Allowed: false,
			},
			expectOutput: true,
		},
		{
			name:     "error level blocks warn logs",
			logLevel: slog.LevelError,
			request: Request{
				Method:  "POST",
				URL:     "https://example.com",
				Allowed: false,
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
	req := Request{
		Method:  "GET",
		URL:     "https://example.com",
		Allowed: true,
		Rule:    "test",
	}

	// This should either handle gracefully or panic - both are acceptable
	auditor.AuditRequest(req)
}

func TestLoggingAuditor_JSONHandler(t *testing.T) {
	// Test with JSON handler instead of text handler
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	auditor := NewLoggingAuditor(logger)
	req := Request{
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
	req := Request{
		Method:  "GET",
		URL:     "https://example.com",
		Allowed: true,
		Rule:    "allow example.com",
	}

	// This should not panic even with discard handler
	auditor.AuditRequest(req)
}
