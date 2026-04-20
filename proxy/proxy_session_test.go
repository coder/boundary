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
	const headerName = "X-Coder-Agent-Firewall-Session-Id"

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
		WithSessionIDMatch("domain="+backendURL.Hostname()),
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
	const headerName = "X-Coder-Agent-Firewall-Session-Id"
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
		WithSessionIDMatch("domain="+backendURL.Hostname()),
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
	const headerName = "X-Coder-Agent-Firewall-Session-Id"

	recorder := &recordingHandler{}
	backend := httptest.NewServer(recorder)
	defer backend.Close()

	backendURL, err := url.Parse(backend.URL)
	require.NoError(t, err)

	// No WithSessionIDHeader option → sessionIDHeader stays empty → disabled.
	pt := NewProxyTest(t,
		WithProxyPort(8083),
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

// TestSessionIDHeader_NotInjectedWithoutMatchRules verifies that no header is
// injected when no session-ID match rules are configured, even if a session ID
// and header name are set. This covers the new "empty rules = never inject"
// default introduced with the match-rule gating feature.
func TestSessionIDHeader_NotInjectedWithoutMatchRules(t *testing.T) {
	const headerName = "X-Coder-Agent-Firewall-Session-Id"

	recorder := &recordingHandler{}
	backend := httptest.NewServer(recorder)
	defer backend.Close()

	backendURL, err := url.Parse(backend.URL)
	require.NoError(t, err)

	// No WithSessionIDMatch → match engine has zero rules → header must not appear.
	pt := NewProxyTest(t,
		WithProxyPort(8088),
		WithAllowedDomain(backendURL.Hostname()),
		WithSessionID("some-session-id"),
		WithSessionIDHeader(headerName),
	).Start()
	defer pt.Stop()

	resp, err := pt.proxyClient.Get(backend.URL + "/path")
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode)

	got := recorder.last()
	require.NotNil(t, got)
	assert.Empty(t, got.Get(headerName),
		"upstream should not receive the session ID header when no match rules are configured")
}

// TestSessionIDHeader_InjectedOnlyOnMatchingRequests verifies selective
// injection: the header is stamped on requests whose URL matches a session-ID
// rule but not on requests to a different backend.
func TestSessionIDHeader_InjectedOnlyOnMatchingRequests(t *testing.T) {
	const sessionID = "selective-session-id"
	const headerName = "X-Coder-Agent-Firewall-Session-Id"

	// Two upstream backends: one that matches the session-ID rule, one that does not.
	matchedRecorder := &recordingHandler{}
	matchedBackend := httptest.NewServer(matchedRecorder)
	defer matchedBackend.Close()

	unmatchedRecorder := &recordingHandler{}
	unmatchedBackend := httptest.NewServer(unmatchedRecorder)
	defer unmatchedBackend.Close()

	matchedURL, err := url.Parse(matchedBackend.URL)
	require.NoError(t, err)
	unmatchedURL, err := url.Parse(unmatchedBackend.URL)
	require.NoError(t, err)

	// Allow both backends through the proxy, but only inject the header for the
	// matched backend's path prefix.
	pt := NewProxyTest(t,
		WithProxyPort(8089),
		WithAllowedDomain(matchedURL.Hostname()),
		WithAllowedDomain(unmatchedURL.Hostname()),
		WithSessionID(sessionID),
		WithSessionIDHeader(headerName),
		WithSessionIDMatch("domain="+matchedURL.Hostname()+" path=/api/v2/aibridge/*"),
	).Start()
	defer pt.Stop()

	// Request to the matched backend on the matching path.
	resp, err := pt.proxyClient.Get(matchedBackend.URL + "/api/v2/aibridge/anthropic/v1/messages")
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode)

	got := matchedRecorder.last()
	require.NotNil(t, got)
	assert.Equal(t, sessionID, got.Get(headerName),
		"matched backend should receive the session ID header")

	// Request to the unmatched backend: no header.
	resp, err = pt.proxyClient.Get(unmatchedBackend.URL + "/other/path")
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode)

	got = unmatchedRecorder.last()
	require.NotNil(t, got)
	assert.Empty(t, got.Get(headerName),
		"unmatched backend should not receive the session ID header")
}
