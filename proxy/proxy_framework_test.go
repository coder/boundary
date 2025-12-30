package proxy

import (
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/user"
	"strconv"
	"testing"
	"time"

	"github.com/coder/boundary/rulesengine"
	boundary_tls "github.com/coder/boundary/tls"
	"github.com/stretchr/testify/require"
)

// ProxyTest is a high-level test framework for proxy tests
type ProxyTest struct {
	t              *testing.T
	server         *Server
	client         *http.Client
	port           int
	useCertManager bool
	configDir      string
	startupDelay   time.Duration
}

// ProxyTestOption is a function that configures ProxyTest
type ProxyTestOption func(*ProxyTest)

// NewProxyTest creates a new ProxyTest instance
func NewProxyTest(t *testing.T, opts ...ProxyTestOption) *ProxyTest {
	pt := &ProxyTest{
		t:              t,
		port:           8080,
		useCertManager: false,
		configDir:      "/tmp/boundary",
		startupDelay:   100 * time.Millisecond,
	}

	// Apply options
	for _, opt := range opts {
		opt(pt)
	}

	return pt
}

// WithProxyPort sets the proxy server port
func WithProxyPort(port int) ProxyTestOption {
	return func(pt *ProxyTest) {
		pt.port = port
	}
}

// WithCertManager enables TLS certificate manager
func WithCertManager(configDir string) ProxyTestOption {
	return func(pt *ProxyTest) {
		pt.useCertManager = true
		pt.configDir = configDir
	}
}

// WithStartupDelay sets how long to wait after starting server before making requests
func WithStartupDelay(delay time.Duration) ProxyTestOption {
	return func(pt *ProxyTest) {
		pt.startupDelay = delay
	}
}

// Start starts the proxy server
func (pt *ProxyTest) Start() *ProxyTest {
	pt.t.Helper()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	testRules, err := rulesengine.ParseAllowSpecs([]string{"method=*"})
	require.NoError(pt.t, err, "Failed to parse test rules")

	ruleEngine := rulesengine.NewRuleEngine(testRules, logger)
	auditor := &mockAuditor{}

	var tlsConfig *tls.Config
	if pt.useCertManager {
		currentUser, err := user.Current()
		require.NoError(pt.t, err, "Failed to get current user")

		uid, _ := strconv.Atoi(currentUser.Uid)
		gid, _ := strconv.Atoi(currentUser.Gid)

		certManager, err := boundary_tls.NewCertificateManager(boundary_tls.Config{
			Logger:    logger,
			ConfigDir: pt.configDir,
			Uid:       uid,
			Gid:       gid,
		})
		require.NoError(pt.t, err, "Failed to create certificate manager")

		tlsConfig, err = certManager.SetupTLSAndWriteCACert()
		require.NoError(pt.t, err, "Failed to setup TLS")
	} else {
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}

	pt.server = NewProxyServer(Config{
		HTTPPort:   pt.port,
		RuleEngine: ruleEngine,
		Auditor:    auditor,
		Logger:     logger,
		TLSConfig:  tlsConfig,
	})

	err = pt.server.Start()
	require.NoError(pt.t, err, "Failed to start server")

	// Give server time to start
	time.Sleep(pt.startupDelay)

	// Create HTTP client
	pt.client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Skip cert verification for testing
			},
		},
		Timeout: 5 * time.Second,
	}

	return pt
}

// Stop gracefully stops the proxy server
func (pt *ProxyTest) Stop() {
	if pt.server != nil {
		err := pt.server.Stop()
		if err != nil {
			pt.t.Logf("Failed to stop proxy server: %v", err)
		}
	}
}

// ExpectAllowed makes a request through the proxy and expects it to be allowed with the given response body
func (pt *ProxyTest) ExpectAllowed(proxyURL, hostHeader, expectedBody string) {
	pt.t.Helper()

	req, err := http.NewRequest("GET", proxyURL, nil)
	require.NoError(pt.t, err, "Failed to create request")
	req.Host = hostHeader

	resp, err := pt.client.Do(req)
	require.NoError(pt.t, err, "Failed to make request")
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(resp.Body)
	require.NoError(pt.t, err, "Failed to read response body")

	require.Equal(pt.t, expectedBody, string(body), "Expected response body does not match")
}

// ExpectAllowedContains makes a request through the proxy and expects it to be allowed, checking that response contains the given text
func (pt *ProxyTest) ExpectAllowedContains(proxyURL, hostHeader, containsText string) {
	pt.t.Helper()

	req, err := http.NewRequest("GET", proxyURL, nil)
	require.NoError(pt.t, err, "Failed to create request")
	req.Host = hostHeader

	resp, err := pt.client.Do(req)
	require.NoError(pt.t, err, "Failed to make request")
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(resp.Body)
	require.NoError(pt.t, err, "Failed to read response body")

	require.Contains(pt.t, string(body), containsText, "Response does not contain expected text")
}
