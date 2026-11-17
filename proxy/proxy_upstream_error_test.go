package proxy

import (
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// unreachableAddr returns a loopback address that refuses connections.
func unreachableAddr(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	return addr
}

// TestProxyServerUpstreamUnreachable verifies that an allowed request whose
// upstream cannot be reached gets a 502 Bad Gateway instead of an empty
// reply or a hung connection.
func TestProxyServerUpstreamUnreachable(t *testing.T) {
	addr := unreachableAddr(t)

	pt := NewProxyTest(t,
		WithCertManager(t.TempDir()),
		WithAllowedDomain("127.0.0.1"),
	).Start()
	defer pt.Stop()

	expectBadGateway := func(t *testing.T, client *http.Client, url, host string) {
		t.Helper()

		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
		require.NoError(t, err)
		req.Host = host

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close() //nolint:errcheck

		require.Equal(t, http.StatusBadGateway, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Contains(t, string(body), addr)
	}

	t.Run("TransparentHTTP", func(t *testing.T) {
		expectBadGateway(t, pt.client, "http://localhost:8080/", addr)
	})

	t.Run("TransparentHTTPS", func(t *testing.T) {
		expectBadGateway(t, pt.client, "https://localhost:8080/", addr)
	})

	t.Run("ExplicitProxyHTTP", func(t *testing.T) {
		expectBadGateway(t, pt.proxyClient, "http://"+addr+"/", "")
	})

	// The CONNECT tunnel serves many requests on one connection, so a
	// failed forward must still produce a response. Otherwise the client
	// waits for it while the proxy waits for the next request.
	t.Run("CONNECTTunnel", func(t *testing.T) {
		// The CONNECT target only sets the TLS server name, which must be a
		// hostname. The Host header below picks the upstream.
		tunnel, err := pt.establishExplicitCONNECT("localhost:443")
		require.NoError(t, err)
		defer tunnel.close() //nolint:errcheck
		require.NoError(t, tunnel.tlsConn.SetDeadline(time.Now().Add(5*time.Second)))

		// Two requests show that the tunnel stays usable after a failure.
		for range 2 {
			_, err := tunnel.tlsConn.Write([]byte("GET / HTTP/1.1\r\nHost: " + addr + "\r\n\r\n"))
			require.NoError(t, err)

			resp, err := http.ReadResponse(tunnel.reader, nil)
			require.NoError(t, err)
			_, err = io.Copy(io.Discard, resp.Body)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			require.Equal(t, http.StatusBadGateway, resp.StatusCode)
		}
	})
}
