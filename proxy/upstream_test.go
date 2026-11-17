package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestProxyServerUpstreamProxy_ForwardsAllowedHTTPAndHTTPS(t *testing.T) {
	upstream := newRecordingUpstreamProxy(t)
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)

	forwardTransport := http.DefaultTransport.(*http.Transport).Clone()
	forwardTransport.Proxy = http.ProxyURL(upstreamURL)
	forwardTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	forwardTransport.DisableKeepAlives = true

	httpBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("http-ok"))
	}))
	defer httpBackend.Close()

	httpsBackend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("https-ok"))
	}))
	defer httpsBackend.Close()

	httpsBackendURL, err := url.Parse(httpsBackend.URL)
	require.NoError(t, err)
	httpsURL := "https://localhost:" + httpsBackendURL.Port()

	pt := NewProxyTest(t,
		WithProxyPort(freeTCPPort(t)),
		WithCertManager(t.TempDir()),
		WithAllowedDomain("127.0.0.1"),
		WithAllowedDomain("localhost"),
		WithForwardTransport(forwardTransport),
	).Start()
	defer pt.Stop()

	resp, err := pt.proxyClient.Get(httpBackend.URL)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "http-ok", string(body))

	resp, err = pt.proxyClient.Get(httpsURL)
	require.NoError(t, err)
	body, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "https-ok", string(body))

	require.Equal(t, int32(1), upstream.HTTPRequests())
	require.Equal(t, int32(1), upstream.CONNECTRequests())
	require.Contains(t, upstream.URLs(), httpBackend.URL+"/")
}

func TestProxyServerUpstreamProxy_DeniedRequestsNeverReachUpstream(t *testing.T) {
	upstream := newRecordingUpstreamProxy(t)
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)

	forwardTransport := http.DefaultTransport.(*http.Transport).Clone()
	forwardTransport.Proxy = http.ProxyURL(upstreamURL)
	forwardTransport.DisableKeepAlives = true

	pt := NewProxyTest(t,
		WithProxyPort(freeTCPPort(t)),
		WithCertManager(t.TempDir()),
		WithForwardTransport(forwardTransport),
	).Start()
	defer pt.Stop()

	pt.ExpectGetViaProxy("http://denied.example.test/exfil", http.StatusForbidden)
	pt.ExpectGetViaProxy("https://denied.example.test/exfil", http.StatusForbidden)

	require.Equal(t, int32(0), upstream.HTTPRequests())
	require.Equal(t, int32(0), upstream.CONNECTRequests())
}

func TestNewForwardTransport_UsesConfiguredUpstreamProxy(t *testing.T) {
	t.Parallel()

	transport, err := NewForwardTransport("http://user:pass@proxy.corp:3128")
	require.NoError(t, err)
	require.NotNil(t, transport)

	req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
	require.NoError(t, err)

	proxyURL, err := transport.(*http.Transport).Proxy(req)
	require.NoError(t, err)
	require.Equal(t, "http://user:pass@proxy.corp:3128", proxyURL.String())
	require.Equal(t, "http://proxy.corp:3128", RedactProxyURL(proxyURL.String()))
}

type recordingUpstreamProxy struct {
	*httptest.Server

	httpRequests    atomic.Int32
	connectRequests atomic.Int32

	mu   sync.Mutex
	urls []string
}

func newRecordingUpstreamProxy(t *testing.T) *recordingUpstreamProxy {
	t.Helper()

	proxy := &recordingUpstreamProxy{}
	proxy.Server = httptest.NewServer(http.HandlerFunc(proxy.handle))
	return proxy
}

func (p *recordingUpstreamProxy) HTTPRequests() int32 {
	return p.httpRequests.Load()
}

func (p *recordingUpstreamProxy) CONNECTRequests() int32 {
	return p.connectRequests.Load()
}

func (p *recordingUpstreamProxy) URLs() []string {
	p.mu.Lock()
	defer p.mu.Unlock()

	urls := make([]string, len(p.urls))
	copy(urls, p.urls)
	return urls
}

func (p *recordingUpstreamProxy) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.connectRequests.Add(1)
		p.handleCONNECT(w, r)
		return
	}

	p.httpRequests.Add(1)
	p.recordURL(r.URL.String())

	if !r.URL.IsAbs() {
		http.Error(w, "proxy request URL must be absolute", http.StatusBadRequest)
		return
	}

	outReq := r.Clone(context.Background())
	outReq.RequestURI = ""

	resp, err := http.DefaultTransport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close() //nolint:errcheck

	for name, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (p *recordingUpstreamProxy) handleCONNECT(w http.ResponseWriter, r *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close() //nolint:errcheck

	targetConn, err := net.DialTimeout("tcp", r.Host, 5*time.Second)
	if err != nil {
		_, _ = fmt.Fprintf(clientConn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer targetConn.Close() //nolint:errcheck

	_, _ = fmt.Fprintf(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n")

	go func() {
		_, _ = io.Copy(targetConn, clientConn)
		_ = targetConn.Close()
	}()
	_, _ = io.Copy(clientConn, targetConn)
}

func (p *recordingUpstreamProxy) recordURL(raw string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.urls = append(p.urls, raw)
}

func freeTCPPort(t *testing.T) int {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close() //nolint:errcheck

	return ln.Addr().(*net.TCPAddr).Port
}
