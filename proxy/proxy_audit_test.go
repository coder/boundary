package proxy

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/coder/boundary/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// capturingAuditor captures all audit requests for test verification.
type capturingAuditor struct {
	mu       sync.Mutex
	requests []audit.Request
}

func (c *capturingAuditor) AuditRequest(req audit.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requests = append(c.requests, req)
}

func (c *capturingAuditor) getRequests() []audit.Request {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]audit.Request{}, c.requests...)
}

func TestSequenceNumberIncrementsAcrossRequestTypes(t *testing.T) {
	// Plain HTTP backend — used by the plain HTTP request.
	httpBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer httpBackend.Close()

	// TLS backend — used by both the implicit-CONNECT and explicit-CONNECT
	// requests. The proxy needs InsecureSkipVerify to trust its self-signed cert.
	tlsBackend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer tlsBackend.Close()

	httpBackendURL, err := url.Parse(httpBackend.URL)
	require.NoError(t, err)
	tlsBackendURL, err := url.Parse(tlsBackend.URL)
	require.NoError(t, err)

	// TLS SNI requires a hostname, not an IP address. httptest servers bind to
	// 127.0.0.1, so rewrite the host to "localhost" for all TLS connections so
	// that the proxy's cert manager receives a proper SNI value.
	tlsHost := "localhost:" + tlsBackendURL.Port()
	tlsURL := "https://" + tlsHost

	auditor := &capturingAuditor{}

	//nolint:gosec
	insecureTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	pt := NewProxyTest(t,
		WithCertManager(t.TempDir()),
		WithAllowedDomain(httpBackendURL.Hostname()),
		WithAllowedDomain("localhost"),
		WithAuditor(auditor),
		WithForwardTransport(insecureTransport),
	).Start()
	defer pt.Stop()

	// Request 1: plain HTTP — handleHTTPConnection → processHTTPRequest(https=false)
	resp, err := pt.proxyClient.Get(httpBackend.URL + "/")
	require.NoError(t, err)
	resp.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Request 2: HTTPS via implicit CONNECT — Go's transport automatically sends
	// CONNECT for https:// URLs → handleCONNECTTunnel → processHTTPRequest(https=true)
	resp, err = pt.proxyClient.Get(tlsURL + "/")
	require.NoError(t, err)
	resp.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Request 3: inside an explicit CONNECT tunnel — handleCONNECTTunnel →
	// processHTTPRequest(https=true), driven by a manually established tunnel.
	tunnel, err := pt.establishExplicitCONNECT(tlsHost)
	require.NoError(t, err)
	defer tunnel.close() //nolint:errcheck
	_, err = tunnel.sendRequest(tlsHost, "/")
	require.NoError(t, err)

	requests := auditor.getRequests()
	require.Len(t, requests, 3, "expected one audit record per request")

	assert.Equal(t, int32(0), requests[0].SequenceNumber, "HTTP request must have sequence number 0")
	assert.Equal(t, int32(1), requests[1].SequenceNumber, "implicit-CONNECT request must have sequence number 1")
	assert.Equal(t, int32(2), requests[2].SequenceNumber, "explicit-CONNECT tunnel request must have sequence number 2")
}

func TestAuditURLIsFullyFormed_HTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	auditor := &capturingAuditor{}

	pt := NewProxyTest(t,
		WithCertManager(t.TempDir()),
		WithAllowedRule("domain="+serverURL.Hostname()+" path=/allowed/*"),
		WithAuditor(auditor),
	).Start()
	defer pt.Stop()

	t.Run("allowed", func(t *testing.T) {
		resp, err := pt.proxyClient.Get(server.URL + "/allowed/path?q=1")
		require.NoError(t, err)
		defer func() {
			err = resp.Body.Close()
			require.NoError(t, err)
		}()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		requests := auditor.getRequests()
		require.NotEmpty(t, requests)

		req := requests[len(requests)-1]
		require.True(t, req.Allowed)

		expectedURL := "http://" + net.JoinHostPort(serverURL.Hostname(), serverURL.Port()) + "/allowed/path?q=1"
		assert.Equal(t, expectedURL, req.URL)
	})

	t.Run("denied", func(t *testing.T) {
		resp, err := pt.proxyClient.Get(server.URL + "/denied/path")
		require.NoError(t, err)
		defer func() {
			err = resp.Body.Close()
			require.NoError(t, err)
		}()
		require.Equal(t, http.StatusForbidden, resp.StatusCode)

		requests := auditor.getRequests()
		require.NotEmpty(t, requests)

		req := requests[len(requests)-1]
		require.False(t, req.Allowed)

		expectedURL := "http://" + net.JoinHostPort(serverURL.Hostname(), serverURL.Port()) + "/denied/path"
		assert.Equal(t, expectedURL, req.URL)
	})
}

func TestAuditURLIsFullyFormed_HTTPS(t *testing.T) {
	auditor := &capturingAuditor{}

	pt := NewProxyTest(t,
		WithCertManager(t.TempDir()),
		WithAllowedDomain("dev.coder.com"),
		WithAuditor(auditor),
	).Start()
	defer pt.Stop()

	tunnel, err := pt.establishExplicitCONNECT("dev.coder.com:443")
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, tunnel.close())
	}()

	t.Run("allowed", func(t *testing.T) {
		_, err := tunnel.sendRequest("dev.coder.com", "/api/v2?q=1")
		require.NoError(t, err)

		requests := auditor.getRequests()
		require.NotEmpty(t, requests)

		req := requests[len(requests)-1]
		require.True(t, req.Allowed)

		assert.Equal(t, "https://dev.coder.com/api/v2?q=1", req.URL)
	})

	t.Run("denied", func(t *testing.T) {
		err := tunnel.sendRequestAndExpectDeny("blocked.example.com", "/some/path")
		require.NoError(t, err)

		requests := auditor.getRequests()
		require.NotEmpty(t, requests)

		req := requests[len(requests)-1]
		require.False(t, req.Allowed)

		assert.Equal(t, "https://blocked.example.com/some/path", req.URL)
	})
}
