package proxy

import (
	"crypto/tls"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"strconv"
	"testing"
	"time"

	boundary_tls "github.com/coder/boundary/tls"
	"github.com/stretchr/testify/require"

	"github.com/coder/boundary/audit"
	"github.com/coder/boundary/rulesengine"
)

// mockAuditor is a simple mock auditor for testing
type mockAuditor struct{}

func (m *mockAuditor) AuditRequest(req audit.Request) {
	// No-op for testing
}

// TestProxyServerBasicHTTP tests basic HTTP request handling
func TestProxyServerBasicHTTP(t *testing.T) {
	pt := NewProxyTest(t).
		Start()
	defer pt.Stop()

	t.Run("BasicHTTPRequest", func(t *testing.T) {
		expectedResponse := `{
  "userId": 1,
  "id": 1,
  "title": "delectus aut autem",
  "completed": false
}`
		pt.ExpectAllowed("http://localhost:8080/todos/1", "jsonplaceholder.typicode.com", expectedResponse)
	})
}

// TestProxyServerBasicHTTPS tests basic HTTPS request handling
func TestProxyServerBasicHTTPS(t *testing.T) {
	pt := NewProxyTest(t,
		WithCertManager("/tmp/boundary"),
	).
		Start()
	defer pt.Stop()

	t.Run("BasicHTTPSRequest", func(t *testing.T) {
		expectedResponse := `{"message":"👋"}
`
		pt.ExpectAllowed("https://localhost:8080/api/v2", "dev.coder.com", expectedResponse)
	})
}

// TestProxyServerCONNECT tests HTTP CONNECT method for HTTPS tunneling
func TestProxyServerCONNECT(t *testing.T) {
	t.Skip()

	// Create test logger
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	// Create test rules (allow all for testing)
	testRules, err := rulesengine.ParseAllowSpecs([]string{"method=*"})
	if err != nil {
		t.Fatalf("Failed to parse test rules: %v", err)
	}

	// Create rule engine
	ruleEngine := rulesengine.NewRuleEngine(testRules, logger)

	// Create mock auditor
	auditor := &mockAuditor{}

	// Get current user for TLS setup
	currentUser, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}

	uid, _ := strconv.Atoi(currentUser.Uid)
	gid, _ := strconv.Atoi(currentUser.Gid)

	// Create TLS certificate manager
	certManager, err := boundary_tls.NewCertificateManager(boundary_tls.Config{
		Logger:    logger,
		ConfigDir: "/tmp/boundary_connect_test",
		Uid:       uid,
		Gid:       gid,
	})
	require.NoError(t, err)

	// Setup TLS to get cert path for proxy
	tlsConfig, err := certManager.SetupTLSAndWriteCACert()
	require.NoError(t, err)

	// Create proxy server
	server := NewProxyServer(Config{
		HTTPPort: 8080,

		RuleEngine: ruleEngine,
		Auditor:    auditor,
		Logger:     logger,
		TLSConfig:  tlsConfig,
	})

	// Start server
	err = server.Start()
	require.NoError(t, err)

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Test HTTPS request through proxy transport (automatic CONNECT)
	t.Run("HTTPSRequestThroughProxyTransport", func(t *testing.T) {
		// Create proxy URL
		proxyURL, err := url.Parse("http://localhost:8080")
		require.NoError(t, err)

		// Create HTTP client with proxy transport
		client := &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, // Skip cert verification for testing
				},
			},
			Timeout: 10 * time.Second,
		}

		// Because this is HTTPS, Go will issue CONNECT localhost:8080 → dev.coder.com:443
		resp, err := client.Get("https://dev.coder.com/api/v2")
		require.NoError(t, err)

		// Read response
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())

		// Verify response contains expected content
		expectedResponse := `{"message":"👋"}
`
		require.Equal(t, expectedResponse, string(body))
	})

	// Test HTTP request through proxy transport
	t.Run("HTTPRequestThroughProxyTransport", func(t *testing.T) {
		// Create proxy URL
		proxyURL, err := url.Parse("http://localhost:8080")
		require.NoError(t, err)

		// Create HTTP client with proxy transport
		client := &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
			},
			Timeout: 10 * time.Second,
		}

		// For HTTP requests, Go will send the request directly to the proxy
		// The proxy will forward it to the target server
		resp, err := client.Get("http://jsonplaceholder.typicode.com/todos/1")
		require.NoError(t, err)

		// Read response
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())

		// Verify response contains expected content
		expectedResponse := `{
  "userId": 1,
  "id": 1,
  "title": "delectus aut autem",
  "completed": false
}`
		require.Equal(t, expectedResponse, string(body))
	})

	err = server.Stop()
	require.NoError(t, err)
}
