package proxy

import (
	"testing"
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
