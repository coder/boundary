package proxy

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/http"
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

// TestServePprofLogsOnlyUnexpectedErrors verifies that a normal pprof
// shutdown is not reported as an error, while a real serve failure is.
func TestServePprofLogsOnlyUnexpectedErrors(t *testing.T) {
	newServer := func(logs *bytes.Buffer) *Server {
		return &Server{
			logger:      slog.New(slog.NewTextHandler(logs, nil)),
			pprofServer: &http.Server{},
		}
	}

	t.Run("ShutdownIsNotAnError", func(t *testing.T) {
		var logs bytes.Buffer
		p := newServer(&logs)
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)

		done := make(chan struct{})
		go func() {
			p.servePprof(ln)
			close(done)
		}()
		require.NoError(t, p.pprofServer.Shutdown(context.Background()))
		<-done

		require.NotContains(t, logs.String(), "pprof server error")
	})

	t.Run("ServeFailureIsLogged", func(t *testing.T) {
		var logs bytes.Buffer
		p := newServer(&logs)
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		// Serve fails immediately on a closed listener.
		require.NoError(t, ln.Close())

		p.servePprof(ln)

		require.Contains(t, logs.String(), "pprof server error")
	})
}
