package nsjail

import "testing"

func TestHTTPPath(t *testing.T) {
	// Create and configure nsjail test
	nt := NewNSJailTest(t,
		WithNSJailAllowedRule("domain=jsonplaceholder.typicode.com path=/todos/1"),
		WithNSJailAllowedRule("domain=dev.coder.com path=/api/v2"),
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

	// Test denied HTTP request
	t.Run("HTTPRequestThroughBoundary", func(t *testing.T) {
		nt.ExpectDeny("http://jsonplaceholder.typicode.com/todos/2")
	})

	// Test denied HTTPS request
	t.Run("HTTPRequestThroughBoundary", func(t *testing.T) {
		nt.ExpectDeny("https://dev.coder.com/api/v3")
	})
}

func TestHTTPPathWildCardSymbol(t *testing.T) {
	// Create and configure nsjail test
	nt := NewNSJailTest(t,
		WithNSJailAllowedRule("domain=jsonplaceholder.typicode.com path=/todos/*"),
		WithNSJailAllowedRule("domain=dev.coder.com path=/api/*"),
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

	t.Run("HTTPRequestThroughBoundary", func(t *testing.T) {
		expectedResponse := `{
  "userId": 1,
  "id": 2,
  "title": "quis ut nam facilis et officia qui",
  "completed": false
}`
		nt.ExpectAllowed("http://jsonplaceholder.typicode.com/todos/2", expectedResponse)
	})

	// Test allowed HTTPS request
	t.Run("HTTPSRequestThroughBoundary", func(t *testing.T) {
		expectedResponse := `{"message":"👋"}
`
		nt.ExpectAllowed("https://dev.coder.com/api/v2", expectedResponse)
	})

	// Test denied HTTP request
	t.Run("HTTPRequestThroughBoundary", func(t *testing.T) {
		nt.ExpectDeny("http://jsonplaceholder.typicode.com")
		nt.ExpectDeny("http://jsonplaceholder.typicode.com/todos")
	})

	//// Test denied HTTPS request
	t.Run("HTTPRequestThroughBoundary", func(t *testing.T) {
		nt.ExpectDeny("https://dev.coder.com")
		nt.ExpectDeny("https://dev.coder.com/api")
	})
}

func TestHTTPMultiPath(t *testing.T) {
	// Create and configure nsjail test
	nt := NewNSJailTest(t,
		WithNSJailAllowedRule("domain=jsonplaceholder.typicode.com path=/todos/1,/todos/2"),
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

	t.Run("HTTPRequestThroughBoundary", func(t *testing.T) {
		expectedResponse := `{
  "userId": 1,
  "id": 2,
  "title": "quis ut nam facilis et officia qui",
  "completed": false
}`
		nt.ExpectAllowed("http://jsonplaceholder.typicode.com/todos/2", expectedResponse)
	})

	t.Run("HTTPRequestThroughBoundary", func(t *testing.T) {
		nt.ExpectDeny("http://jsonplaceholder.typicode.com/todos/3")
	})
}
