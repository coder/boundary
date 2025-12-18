package nsjail

import "testing"

func TestNamespaceJail(t *testing.T) {
	// Create and configure nsjail test
	nt := NewNSJailTest(t,
		WithNSJailAllowedDomain("dev.coder.com"),
		WithNSJailAllowedDomain("jsonplaceholder.typicode.com"),
		WithNSJailLogLevel("debug"),
	).
		Build().
		Start()

	// Ensure cleanup
	defer nt.Stop()

	// Test allowed HTTP request
	t.Run("HTTPRequestThroughBoundary", func(t *testing.T) {
		expectedResponse := `{
  "userId": 1,
  "id": 1,
  "title": "delectus aut autem",
  "completed": false
}`
		nt.ExpectAllowed("http://jsonplaceholder.typicode.com/todos/1", expectedResponse)
	})

	// Test allowed HTTPS request
	t.Run("HTTPSRequestThroughBoundary", func(t *testing.T) {
		expectedResponse := `{"message":"👋"}
`
		nt.ExpectAllowed("https://dev.coder.com/api/v2", expectedResponse)
	})

	// Test blocked HTTP request
	t.Run("HTTPBlockedDomainTest", func(t *testing.T) {
		nt.ExpectDeny("http://example.com")
	})

	// Test blocked HTTPS request
	t.Run("HTTPSBlockedDomainTest", func(t *testing.T) {
		nt.ExpectDeny("https://example.com")
	})
}
