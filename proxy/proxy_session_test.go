package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// WithSessionIDHeader sets the session-ID header name on the proxy server under test.
func WithSessionIDHeader(header string) ProxyTestOption {
	return func(pt *ProxyTest) {
		pt.sessionIDHeader = header
	}
}

// WithSessionID sets the session ID on the proxy server under test.
func WithSessionID(id string) ProxyTestOption {
	return func(pt *ProxyTest) {
		pt.sessionID = id
	}
}

// recordingHandler captures the headers received by an upstream server.
type recordingHandler struct {
	mu      sync.Mutex
	headers []http.Header
}

func (r *recordingHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	r.headers = append(r.headers, req.Header.Clone())
	r.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func (r *recordingHandler) last() http.Header {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.headers) == 0 {
		return nil
	}
	return r.headers[len(r.headers)-1]
}

// TestSessionIDHeader_InjectedOnForwardedRequest verifies that the configured
// session ID header is stamped on requests forwarded to the upstream server,
// and that it overwrites any value the jailed client set.
func TestSessionIDHeader_InjectedOnForwardedRequest(t *testing.T) {
	const sessionID = "test-session-uuid-1234"
	const headerName = "X-Agent-Firewall-Session-Id"

	recorder := &recordingHandler{}
	backend := httptest.NewServer(recorder)
	defer backend.Close()

	backendURL, err := url.Parse(backend.URL)
	require.NoError(t, err)

	pt := NewProxyTest(t,
		WithProxyPort(8085),
		WithAllowedDomain(backendURL.Hostname()),
		WithSessionID(sessionID),
		WithSessionIDHeader(headerName),
	).Start()
	defer pt.Stop()

	// Make a request through the proxy; the client does not set the header.
	resp, err := pt.proxyClient.Get(backend.URL + "/path")
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode)

	got := recorder.last()
	require.NotNil(t, got)
	assert.Equal(t, sessionID, got.Get(headerName),
		"upstream should receive the session ID header from boundary")
}

// TestSessionIDHeader_OverwritesClientValue ensures boundary's value wins even
// when the jailed process has already set the same header.
func TestSessionIDHeader_OverwritesClientValue(t *testing.T) {
	const sessionID = "boundary-session-uuid"
	const headerName = "X-Agent-Firewall-Session-Id"
	const clientValue = "evil-client-forged-value"

	recorder := &recordingHandler{}
	backend := httptest.NewServer(recorder)
	defer backend.Close()

	backendURL, err := url.Parse(backend.URL)
	require.NoError(t, err)

	pt := NewProxyTest(t,
		WithProxyPort(8086),
		WithAllowedDomain(backendURL.Hostname()),
		WithSessionID(sessionID),
		WithSessionIDHeader(headerName),
	).Start()
	defer pt.Stop()

	// Build a request that includes the header with a forged value.
	req, err := http.NewRequest(http.MethodGet, backend.URL+"/", nil)
	require.NoError(t, err)
	req.Header.Set(headerName, clientValue)

	resp, err := pt.proxyClient.Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	got := recorder.last()
	require.NotNil(t, got)
	assert.Equal(t, sessionID, got.Get(headerName),
		"boundary should overwrite the client-supplied header value")
}

// TestSessionIDHeader_OmittedWhenDisabled verifies that no header is injected
// when SessionIDHeader is empty (i.e. the feature is disabled).
func TestSessionIDHeader_OmittedWhenDisabled(t *testing.T) {
	const headerName = "X-Agent-Firewall-Session-Id"

	recorder := &recordingHandler{}
	backend := httptest.NewServer(recorder)
	defer backend.Close()

	backendURL, err := url.Parse(backend.URL)
	require.NoError(t, err)

	// No WithSessionIDHeader option → sessionIDHeader stays empty → disabled.
	pt := NewProxyTest(t,
		WithProxyPort(8087),
		WithAllowedDomain(backendURL.Hostname()),
		WithSessionID("some-id"),
	).Start()
	defer pt.Stop()

	resp, err := pt.proxyClient.Get(backend.URL + "/path")
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	got := recorder.last()
	require.NotNil(t, got)
	assert.Empty(t, got.Get(headerName),
		"upstream should not receive the session ID header when the feature is disabled")
}
