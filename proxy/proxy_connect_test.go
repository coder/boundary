package proxy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestProxyServerImplicitCONNECT tests HTTP CONNECT method for HTTPS tunneling
// CONNECT happens implicitly when using proxy transport with HTTPS requests
func TestProxyServerImplicitCONNECT(t *testing.T) {
	pt := NewProxyTest(t,
		WithCertManager("/tmp/boundary_connect_test"),
		WithAllowedDomain("dev.coder.com"),
		WithAllowedDomain("jsonplaceholder.typicode.com"),
	).
		Start()
	defer pt.Stop()

	// Test HTTPS request through proxy transport (automatic CONNECT)
	t.Run("HTTPSRequestThroughProxyTransport", func(t *testing.T) {
		expectedResponse := `{"message":"👋"}
`
		// Because this is HTTPS, Go will issue CONNECT localhost:8080 → dev.coder.com:443
		pt.ExpectAllowedViaProxy("https://dev.coder.com/api/v2", expectedResponse)
	})

	// Test HTTP request through proxy transport
	t.Run("HTTPRequestThroughProxyTransport", func(t *testing.T) {
		expectedResponse := `{
  "userId": 1,
  "id": 1,
  "title": "delectus aut autem",
  "completed": false
}`
		// For HTTP requests, Go will send the request directly to the proxy
		// The proxy will forward it to the target server
		pt.ExpectAllowedViaProxy("http://jsonplaceholder.typicode.com/todos/1", expectedResponse)
	})
}

// TestProxyServerExplicitCONNECT tests explicit CONNECT requests with multiple requests over the same tunnel
func TestProxyServerExplicitCONNECT(t *testing.T) {
	pt := NewProxyTest(t,
		WithCertManager("/tmp/boundary_explicit_connect_test"),
		WithAllowedDomain("dev.coder.com"),
		WithAllowedDomain("jsonplaceholder.typicode.com"),
	).
		Start()
	defer pt.Stop()

	t.Run("MultipleRequestsOverExplicitCONNECT", func(t *testing.T) {
		// Establish explicit CONNECT tunnel
		// Note: The CONNECT target is just the tunnel endpoint. The actual destination
		// for each request is determined by the Host header in the HTTP request inside the tunnel.
		tunnel, err := pt.establishExplicitCONNECT("dev.coder.com:443")
		require.NoError(t, err, "Failed to establish CONNECT tunnel")
		defer tunnel.close() //nolint:errcheck

		// Send first request to dev.coder.com over the tunnel
		body1, err := tunnel.sendRequest("dev.coder.com", "/api/v2")
		require.NoError(t, err, "Failed to send first request")
		expectedResponse1 := `{"message":"👋"}
`
		require.Equal(t, expectedResponse1, string(body1), "First response does not match")

		// Send second request to a different domain (jsonplaceholder.typicode.com) over the same tunnel
		body2, err := tunnel.sendRequest("jsonplaceholder.typicode.com", "/todos/1")
		require.NoError(t, err, "Failed to send second request")
		expectedResponse2 := `{
  "userId": 1,
  "id": 1,
  "title": "delectus aut autem",
  "completed": false
}`
		require.Equal(t, expectedResponse2, string(body2), "Second response does not match")
	})
}
