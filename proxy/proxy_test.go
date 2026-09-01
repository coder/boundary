package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestProxyServerBasicHTTP tests basic HTTP request handling
func TestProxyServerBasicHTTP(t *testing.T) {
	pt := NewProxyTest(t,
		WithAllowedDomain("jsonplaceholder.typicode.com"),
	).
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

	t.Run("BlockedHTTPRequest", func(t *testing.T) {
		pt.ExpectDeny("http://localhost:8080/", "example.com")
	})
}

// TestProxyServerPercentEncoding verifies that the proxy preserves
// percent-encoded reserved characters when forwarding requests.
func TestProxyServerPercentEncoding(t *testing.T) {
	pt := NewProxyTest(t,
		WithCertManager(t.TempDir()),
		WithAllowedDomain("127.0.0.1"),
	).Start()
	defer pt.Stop()

	t.Run("PercentEncodedSlash", func(t *testing.T) {
		pt.ExpectRawURI(
			"/npm/npm-all/@sentry%2Fbun",
			"/npm/npm-all/@sentry%2Fbun",
		)
	})
}

// TestProxyServerBasicHTTPS tests basic HTTPS request handling
func TestProxyServerBasicHTTPS(t *testing.T) {
	pt := NewProxyTest(t,
		WithCertManager("/tmp/boundary"),
		WithAllowedDomain("dev.coder.com"),
	).
		Start()
	defer pt.Stop()

	t.Run("BasicHTTPSRequest", func(t *testing.T) {
		expectedResponse := `{"message":"👋"}
`
		pt.ExpectAllowed("https://localhost:8080/api/v2", "dev.coder.com", expectedResponse)
	})

	t.Run("BlockedHTTPSRequest", func(t *testing.T) {
		pt.ExpectDeny("https://localhost:8080/", "example.com")
	})
}

// The proxy serves one request per connection and then closes it, so both the
// forwarded and the blocked response have to say so. Without the signal a
// client that pools sockets reuses one the proxy has already closed.
func TestProxyResponsesSignalConnectionClose(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	pt := NewProxyTest(t, WithAllowedDomain("127.0.0.1")).Start()
	defer pt.Stop()

	t.Run("allowed request", func(t *testing.T) {
		resp, err := pt.proxyClient.Get(backend.URL)
		require.NoError(t, err)
		defer resp.Body.Close() //nolint:errcheck

		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.True(t, resp.Close, "response must tell the client the connection is closing")
	})

	t.Run("blocked request", func(t *testing.T) {
		blocked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer blocked.Close()

		req, err := http.NewRequest(http.MethodGet, blocked.URL, nil)
		require.NoError(t, err)
		req.Host = "example.com"

		resp, err := pt.proxyClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close() //nolint:errcheck

		require.Equal(t, http.StatusForbidden, resp.StatusCode)
		require.True(t, resp.Close, "blocked response must tell the client the connection is closing")
	})
}
