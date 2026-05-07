package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/coder/boundary/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// headerCapturingBackend spins up an httptest.Server that records the
// headers it receives. Call receivedHeaders after the request to inspect
// them.
type headerCapturingBackend struct {
	server  *httptest.Server
	mu      sync.Mutex
	headers http.Header
}

func newHeaderCapturingBackend() *headerCapturingBackend {
	hcb := &headerCapturingBackend{}
	hcb.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hcb.mu.Lock()
		hcb.headers = r.Header.Clone()
		hcb.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	return hcb
}

func (h *headerCapturingBackend) close() { h.server.Close() }

func (h *headerCapturingBackend) receivedHeaders() http.Header {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.headers.Clone()
}

func TestSessionCorrelation_MatchedDomain(t *testing.T) {
	backend := newHeaderCapturingBackend()
	defer backend.close()

	backendURL, err := url.Parse(backend.server.URL)
	require.NoError(t, err)

	pt := NewProxyTest(t,
		WithCertManager(t.TempDir()),
		WithAllowedDomain(backendURL.Hostname()),
		WithSessionCorrelation(config.SessionCorrelationConfig{
			Enabled:       true,
			InjectTargets: []config.InjectTarget{{Domain: backendURL.Hostname()}},
		}),
		WithSessionID("test-session-id-1234"),
	).Start()
	defer pt.Stop()

	resp, err := pt.proxyClient.Get(backend.server.URL + "/api/v2")
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusOK, resp.StatusCode)

	got := backend.receivedHeaders()
	assert.Equal(t, "test-session-id-1234", got.Get(config.SessionIDHeaderName),
		"session ID header must be injected on matching domain")
	assert.Equal(t, "0", got.Get(config.SequenceNumberHeaderName),
		"sequence number header must start at 0")
}

func TestSessionCorrelation_UnmatchedDomain(t *testing.T) {
	backend := newHeaderCapturingBackend()
	defer backend.close()

	backendURL, err := url.Parse(backend.server.URL)
	require.NoError(t, err)

	pt := NewProxyTest(t,
		WithCertManager(t.TempDir()),
		WithAllowedDomain(backendURL.Hostname()),
		WithSessionCorrelation(config.SessionCorrelationConfig{
			Enabled:       true,
			InjectTargets: []config.InjectTarget{{Domain: "other-domain.example.com"}},
		}),
		WithSessionID("test-session-id-1234"),
	).Start()
	defer pt.Stop()

	resp, err := pt.proxyClient.Get(backend.server.URL + "/api/v2")
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusOK, resp.StatusCode)

	got := backend.receivedHeaders()
	assert.Empty(t, got.Get(config.SessionIDHeaderName),
		"session ID header must not be injected on unmatched domain")
	assert.Empty(t, got.Get(config.SequenceNumberHeaderName),
		"sequence number header must not be injected on unmatched domain")
}

func TestSessionCorrelation_Disabled(t *testing.T) {
	backend := newHeaderCapturingBackend()
	defer backend.close()

	backendURL, err := url.Parse(backend.server.URL)
	require.NoError(t, err)

	pt := NewProxyTest(t,
		WithCertManager(t.TempDir()),
		WithAllowedDomain(backendURL.Hostname()),
		WithSessionCorrelation(config.SessionCorrelationConfig{
			Enabled:       false,
			InjectTargets: []config.InjectTarget{{Domain: backendURL.Hostname()}},
		}),
		WithSessionID("test-session-id-1234"),
	).Start()
	defer pt.Stop()

	resp, err := pt.proxyClient.Get(backend.server.URL + "/api/v2")
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusOK, resp.StatusCode)

	got := backend.receivedHeaders()
	assert.Empty(t, got.Get(config.SessionIDHeaderName),
		"session ID header must not be injected when correlation is disabled")
	assert.Empty(t, got.Get(config.SequenceNumberHeaderName),
		"sequence number header must not be injected when correlation is disabled")
}

func TestSessionCorrelation_OverwritesClientValue(t *testing.T) {
	backend := newHeaderCapturingBackend()
	defer backend.close()

	backendURL, err := url.Parse(backend.server.URL)
	require.NoError(t, err)

	pt := NewProxyTest(t,
		WithCertManager(t.TempDir()),
		WithAllowedDomain(backendURL.Hostname()),
		WithSessionCorrelation(config.SessionCorrelationConfig{
			Enabled:       true,
			InjectTargets: []config.InjectTarget{{Domain: backendURL.Hostname()}},
		}),
		WithSessionID("real-session-id"),
	).Start()
	defer pt.Stop()

	// Send a request with client-supplied session correlation headers
	// that should be overwritten by the proxy.
	req, err := http.NewRequest(http.MethodGet, backend.server.URL+"/api/v2", nil)
	require.NoError(t, err)
	req.Header.Set(config.SessionIDHeaderName, "spoofed-session-id")
	req.Header.Set(config.SequenceNumberHeaderName, "99999")

	resp, err := pt.proxyClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusOK, resp.StatusCode)

	got := backend.receivedHeaders()
	assert.Equal(t, "real-session-id", got.Get(config.SessionIDHeaderName),
		"proxy must overwrite client-supplied session ID header")
	assert.Equal(t, "0", got.Get(config.SequenceNumberHeaderName),
		"proxy must overwrite client-supplied sequence number header")
}

func TestSessionCorrelation_PathMatching(t *testing.T) {
	backend := newHeaderCapturingBackend()
	defer backend.close()

	backendURL, err := url.Parse(backend.server.URL)
	require.NoError(t, err)

	pt := NewProxyTest(t,
		WithCertManager(t.TempDir()),
		WithAllowedDomain(backendURL.Hostname()),
		WithSessionCorrelation(config.SessionCorrelationConfig{
			Enabled: true,
			InjectTargets: []config.InjectTarget{{
				Domain: backendURL.Hostname(),
				Path:   "/api/*",
			}},
		}),
		WithSessionID("test-session-id"),
	).Start()
	defer pt.Stop()

	t.Run("matching path", func(t *testing.T) {
		resp, err := pt.proxyClient.Get(backend.server.URL + "/api/v2")
		require.NoError(t, err)
		defer resp.Body.Close() //nolint:errcheck
		require.Equal(t, http.StatusOK, resp.StatusCode)

		got := backend.receivedHeaders()
		assert.Equal(t, "test-session-id", got.Get(config.SessionIDHeaderName),
			"header must be injected when path matches")
	})

	t.Run("non-matching path", func(t *testing.T) {
		resp, err := pt.proxyClient.Get(backend.server.URL + "/other/path")
		require.NoError(t, err)
		defer resp.Body.Close() //nolint:errcheck
		require.Equal(t, http.StatusOK, resp.StatusCode)

		got := backend.receivedHeaders()
		assert.Empty(t, got.Get(config.SessionIDHeaderName),
			"header must not be injected when path does not match")
	})
}

func TestSessionCorrelation_SequenceNumberIncrements(t *testing.T) {
	backend := newHeaderCapturingBackend()
	defer backend.close()

	backendURL, err := url.Parse(backend.server.URL)
	require.NoError(t, err)

	pt := NewProxyTest(t,
		WithCertManager(t.TempDir()),
		WithAllowedDomain(backendURL.Hostname()),
		WithSessionCorrelation(config.SessionCorrelationConfig{
			Enabled:       true,
			InjectTargets: []config.InjectTarget{{Domain: backendURL.Hostname()}},
		}),
		WithSessionID("test-session-id"),
	).Start()
	defer pt.Stop()

	for i, expected := range []string{"0", "1", "2"} {
		resp, err := pt.proxyClient.Get(backend.server.URL + "/api/v2")
		require.NoError(t, err)
		resp.Body.Close() //nolint:errcheck
		require.Equal(t, http.StatusOK, resp.StatusCode)

		got := backend.receivedHeaders()
		assert.Equal(t, expected, got.Get(config.SequenceNumberHeaderName),
			"request %d: sequence number must be %s", i, expected)
	}
}
