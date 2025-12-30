package proxy

import (
	"testing"
)

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
