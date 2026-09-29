package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// echoUpgradeHandler completes an HTTP upgrade to a made-up "echo"
// protocol and then echoes every line it receives. It stands in for
// WebSocket and DERP servers, which use the same handshake.
func echoUpgradeHandler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isUpgradeRequest(r) || r.Header.Get("Upgrade") != "echo" {
			http.Error(w, "upgrade required", http.StatusUpgradeRequired)
			return
		}
		hj, ok := w.(http.Hijacker)
		require.True(t, ok, "response writer must support hijacking")
		conn, rw, err := hj.Hijack()
		require.NoError(t, err)
		defer conn.Close() //nolint:errcheck

		_, err = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: echo\r\nConnection: Upgrade\r\n\r\n")
		require.NoError(t, err)
		require.NoError(t, rw.Flush())

		for {
			line, err := rw.ReadString('\n')
			if err != nil {
				return
			}
			if _, err := rw.WriteString("echo: " + line); err != nil {
				return
			}
			if err := rw.Flush(); err != nil {
				return
			}
		}
	})
}

// upgradeThroughProxy sends an upgrade handshake for backendHost through
// the proxy on conn and returns the buffered reader positioned after the
// response headers, plus the response.
func upgradeThroughProxy(t *testing.T, conn net.Conn, backendHost string) (*bufio.Reader, *http.Response) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "/stream", nil)
	require.NoError(t, err)
	req.Host = backendHost
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "echo")
	require.NoError(t, req.Write(conn))

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	require.NoError(t, err)
	return reader, resp
}

func expectEcho(t *testing.T, conn net.Conn, reader *bufio.Reader, msg string) {
	t.Helper()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	_, err := fmt.Fprintf(conn, "%s\n", msg)
	require.NoError(t, err)
	line, err := reader.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "echo: "+msg+"\n", line)
}

// TestProxyUpgradeHTTP relays a protocol upgrade over plain HTTP through
// the transparent proxy path, the way the Coder agent reaches coderd.
func TestProxyUpgradeHTTP(t *testing.T) {
	backend := httptest.NewServer(echoUpgradeHandler(t))
	defer backend.Close()
	backendHost := strings.TrimPrefix(backend.URL, "http://")

	auditor := &capturingAuditor{}
	pt := NewProxyTest(t,
		WithProxyPort(18090),
		WithAllowedDomain("127.0.0.1"),
		WithAuditor(auditor),
	).Start()
	defer pt.Stop()

	conn, err := net.Dial("tcp", "127.0.0.1:18090")
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck

	reader, resp := upgradeThroughProxy(t, conn, backendHost)
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)
	require.Equal(t, "echo", resp.Header.Get("Upgrade"))

	expectEcho(t, conn, reader, "hello")
	expectEcho(t, conn, reader, "second message on the same stream")

	requests := auditor.getRequests()
	require.Len(t, requests, 1, "only the handshake is audited")
	require.True(t, requests[0].Allowed)
	require.Equal(t, "http://"+backendHost+"/stream", requests[0].URL)
}

// TestProxyUpgradeHTTPS relays an upgrade when the client speaks TLS to the
// proxy and the proxy speaks TLS to the backend.
func TestProxyUpgradeHTTPS(t *testing.T) {
	backend := httptest.NewTLSServer(echoUpgradeHandler(t))
	defer backend.Close()
	backendHost := strings.TrimPrefix(backend.URL, "https://")

	pool := x509.NewCertPool()
	pool.AddCert(backend.Certificate())
	pt := NewProxyTest(t,
		WithProxyPort(18091),
		WithCertManager(t.TempDir()),
		WithAllowedDomain("127.0.0.1"),
		WithForwardTransport(&http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}),
	).Start()
	defer pt.Stop()

	conn, err := tls.Dial("tcp", "127.0.0.1:18091", &tls.Config{ServerName: "localhost", InsecureSkipVerify: true})
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck

	reader, resp := upgradeThroughProxy(t, conn, backendHost)
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)
	expectEcho(t, conn, reader, "over tls")
}

// TestProxyUpgradeDenied blocks an upgrade to a host outside the allowlist
// with the usual 403.
func TestProxyUpgradeDenied(t *testing.T) {
	backend := httptest.NewServer(echoUpgradeHandler(t))
	defer backend.Close()
	backendHost := strings.TrimPrefix(backend.URL, "http://")

	auditor := &capturingAuditor{}
	pt := NewProxyTest(t,
		WithProxyPort(18092),
		WithAllowedDomain("example.com"),
		WithAuditor(auditor),
	).Start()
	defer pt.Stop()

	conn, err := net.Dial("tcp", "127.0.0.1:18092")
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck

	_, resp := upgradeThroughProxy(t, conn, backendHost)
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Contains(t, string(body), "Blocked by Boundary")

	requests := auditor.getRequests()
	require.Len(t, requests, 1)
	require.False(t, requests[0].Allowed)
}

// TestProxyUpgradeDeclined returns the server's answer when it refuses to
// switch protocols.
func TestProxyUpgradeDeclined(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no upgrades here", http.StatusUpgradeRequired)
	}))
	defer backend.Close()
	backendHost := strings.TrimPrefix(backend.URL, "http://")

	pt := NewProxyTest(t,
		WithProxyPort(18093),
		WithAllowedDomain("127.0.0.1"),
	).Start()
	defer pt.Stop()

	conn, err := net.Dial("tcp", "127.0.0.1:18093")
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck

	_, resp := upgradeThroughProxy(t, conn, backendHost)
	require.Equal(t, http.StatusUpgradeRequired, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Contains(t, string(body), "no upgrades here")
}

func TestIsUpgradeRequest(t *testing.T) {
	mk := func(connection, upgrade string) *http.Request {
		req, err := http.NewRequest(http.MethodGet, "http://example.com/", nil)
		require.NoError(t, err)
		if connection != "" {
			req.Header.Set("Connection", connection)
		}
		if upgrade != "" {
			req.Header.Set("Upgrade", upgrade)
		}
		return req
	}
	require.True(t, isUpgradeRequest(mk("Upgrade", "websocket")))
	require.True(t, isUpgradeRequest(mk("keep-alive, Upgrade", "derp")))
	require.True(t, isUpgradeRequest(mk("upgrade", "websocket")))
	require.False(t, isUpgradeRequest(mk("keep-alive", "")))
	require.False(t, isUpgradeRequest(mk("", "websocket")), "Upgrade without Connection: upgrade is not an upgrade")
	require.False(t, isUpgradeRequest(mk("Upgrade", "")))
}
