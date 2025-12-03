package e2e_tests

import (
	"testing"

	"github.com/coder/boundary/e2e_tests/testenv"
)

// This test runs boundary process with such allowed domains:
// - dev.coder.com
// - jsonplaceholder.typicode.com
// It makes sure you can access these domains with curl tool (using both HTTP and HTTPS protocols).
// Then it makes sure you can NOT access example.com domain which is not allowed (using both HTTP and HTTPS protocols).
func TestBoundaryIntegration(t *testing.T) {
	// Create test environment with allowed domains
	env := testenv.NewTestEnv(t,
		testenv.WithAllowRule("domain=dev.coder.com"),
		testenv.WithAllowRule("domain=jsonplaceholder.typicode.com"),
	)
	defer env.Cleanup()
	env.Start()

	// Test HTTP request through boundary (from inside the jail)
	t.Run("HTTPRequestThroughBoundary", func(t *testing.T) {
		expectedResponse := `{
  "userId": 1,
  "id": 1,
  "title": "delectus aut autem",
  "completed": false
}`
		env.AssertResponseEquals("http://jsonplaceholder.typicode.com/todos/1", expectedResponse)
	})

	// Test HTTPS request through boundary (from inside the jail)
	t.Run("HTTPSRequestThroughBoundary", func(t *testing.T) {
		expectedResponse := `{"message":"👋"}
`
		env.AssertResponseEquals("https://dev.coder.com/api/v2", expectedResponse)
	})

	// Test blocked domain (from inside the jail)
	t.Run("HTTPBlockedDomainTest", func(t *testing.T) {
		env.AssertBlocked("http://example.com")
	})

	// Test blocked domain (from inside the jail)
	t.Run("HTTPSBlockedDomainTest", func(t *testing.T) {
		env.AssertBlocked("https://example.com")
	})
}

// This test runs boundary process with such allowed domains:
// - example.com
// It makes sure you can access this domain with curl tool (using both HTTP and HTTPS protocols).
// It indirectly tests that ContentLength header is properly set, otherwise it fails.
func TestContentLengthHeader(t *testing.T) {
	expectedResponse := `<!doctype html><html lang="en"><head><title>Example Domain</title><meta name="viewport" content="width=device-width, initial-scale=1"><style>body{background:#eee;width:60vw;margin:15vh auto;font-family:system-ui,sans-serif}h1{font-size:1.5em}div{opacity:0.8}a:link,a:visited{color:#348}</style><body><div><h1>Example Domain</h1><p>This domain is for use in documentation examples without needing permission. Avoid use in operations.<p><a href="https://iana.org/domains/example">Learn more</a></div></body></html>
`
	env := testenv.NewTestEnv(t,
		testenv.WithAllowRule("domain=example.com"),
	)
	defer env.Cleanup()
	env.Start()

	// Test HTTP request through boundary (from inside the jail)
	t.Run("HTTPRequestThroughBoundary", func(t *testing.T) {
		env.AssertResponseEquals("http://example.com", expectedResponse)
	})

	// Test HTTPS request through boundary (from inside the jail)
	t.Run("HTTPSRequestThroughBoundary", func(t *testing.T) {
		env.AssertResponseEquals("https://example.com", expectedResponse)
	})
}
