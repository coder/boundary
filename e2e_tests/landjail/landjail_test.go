package landjail

import (
	"testing"
)

func TestLandjail(t *testing.T) {
	// Create and configure landjail test
	lt := NewLandjailTest(t,
		WithLandjailAllowedDomain("dev.coder.com"),
		WithLandjailAllowedDomain("jsonplaceholder.typicode.com"),
		WithLandjailLogLevel("debug"),
	).
		Build().
		Start()

	// Ensure cleanup
	defer lt.Stop()

	// Test allowed HTTP request
	t.Run("HTTPRequestThroughBoundary", func(t *testing.T) {
		expectedResponse := `{
  "userId": 1,
  "id": 1,
  "title": "delectus aut autem",
  "completed": false
}`
		lt.ExpectAllowed("http://jsonplaceholder.typicode.com/todos/1", expectedResponse)
	})

	// Test allowed HTTPS request
	t.Run("HTTPSRequestThroughBoundary", func(t *testing.T) {
		expectedResponse := `{"message":"👋"}
`
		lt.ExpectAllowed("https://dev.coder.com/api/v2", expectedResponse)
	})

	// Test blocked HTTP request
	t.Run("HTTPBlockedDomainTest", func(t *testing.T) {
		lt.ExpectDeny("http://example.com")
	})

	// Test blocked HTTPS request
	t.Run("HTTPSBlockedDomainTest", func(t *testing.T) {
		lt.ExpectDeny("https://example.com")
	})
}
