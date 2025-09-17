package proxy

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/coder/boundary/audit"
	"github.com/coder/boundary/rules"
)

// mockAuditor is a simple mock auditor for testing
type mockAuditor struct{}

func (m *mockAuditor) AuditRequest(req audit.Request) {
	// No-op for testing
}

// TestProxyServerBasicHTTP tests basic HTTP request handling
func TestProxyServerBasicHTTP(t *testing.T) {
	// Create test logger
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	// Create test rules (allow all for testing)
	testRules, err := rules.ParseAllowSpecs([]string{"*"})
	if err != nil {
		t.Fatalf("Failed to parse test rules: %v", err)
	}

	// Create rule engine
	ruleEngine := rules.NewRuleEngine(testRules, logger)

	// Create mock auditor
	auditor := &mockAuditor{}

	// Create TLS config (minimal for testing)
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Create proxy server
	server := NewProxyServer(Config{
		HTTPPort:   8080,
		RuleEngine: ruleEngine,
		Auditor:    auditor,
		Logger:     logger,
		TLSConfig:  tlsConfig,
	})

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Start server in goroutine
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- server.Start(ctx)
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Test basic HTTP request
	t.Run("BasicHTTPRequest", func(t *testing.T) {
		// Create HTTP client
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, // Skip cert verification for testing
				},
			},
			Timeout: 5 * time.Second,
		}

		// Make request to proxy
		req, err := http.NewRequest("GET", "http://localhost:8080/todos/1", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		// Override the Host header
		req.Host = "jsonplaceholder.typicode.com"

		// Make the request
		resp, err := client.Do(req)
		require.NoError(t, err)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		resp.Body.Close()

		expectedResponse := `{
  "userId": 1,
  "id": 1,
  "title": "delectus aut autem",
  "completed": false
}`
		require.Equal(t, expectedResponse, string(body))
	})
}
