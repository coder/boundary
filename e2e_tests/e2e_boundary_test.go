package e2e_tests

import "testing"

func TestE2EBoundary(t *testing.T) {
	// Create and configure boundary test
	bt := NewBoundaryTest(t,
		WithAllowedDomain("dev.coder.com"),
		WithAllowedDomain("jsonplaceholder.typicode.com"),
		WithLogLevel("debug"),
	).
		Build().
		Start()

	// Ensure cleanup
	defer bt.Stop()

	// Test allowed HTTP request
	t.Run("HTTPRequestThroughBoundary", func(t *testing.T) {
		expectedResponse := `{
  "userId": 1,
  "id": 1,
  "title": "delectus aut autem",
  "completed": false
}`
		bt.ExpectAllowed("http://jsonplaceholder.typicode.com/todos/1", expectedResponse)
	})

	// Test allowed HTTPS request
	t.Run("HTTPSRequestThroughBoundary", func(t *testing.T) {
		expectedResponse := `{"message":"👋"}
`
		bt.ExpectAllowed("https://dev.coder.com/api/v2", expectedResponse)
	})

	// Test blocked HTTP request
	t.Run("HTTPBlockedDomainTest", func(t *testing.T) {
		bt.ExpectDeny("http://example.com")
	})

	// Test blocked HTTPS request
	t.Run("HTTPSBlockedDomainTest", func(t *testing.T) {
		bt.ExpectDeny("https://example.com")
	})
}
