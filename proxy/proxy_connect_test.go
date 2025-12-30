package proxy

import "testing"

// TestProxyServerImplicitCONNECT tests HTTP CONNECT method for HTTPS tunneling
// CONNECT happens implicitly when using proxy transport with HTTPS requests
func TestProxyServerImplicitCONNECT(t *testing.T) {
	pt := NewProxyTest(t,
		WithCertManager("/tmp/boundary_connect_test"),
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
