package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/coder/boundary/audit"
	"github.com/coder/boundary/config"
	"github.com/coder/boundary/rulesengine"
)

// Server handles HTTP and HTTPS requests with rule-based filtering
type Server struct {
	ruleEngine       rulesengine.Engine
	auditor          audit.Auditor
	logger           *slog.Logger
	tlsConfig        *tls.Config
	httpPort         int
	started          atomic.Bool
	injectEngine     *rulesengine.Engine // nil when session correlation is disabled
	sessionID        string
	seqCounter       audit.SequenceCounter
	forwardTransport http.RoundTripper

	listener     net.Listener
	pprofServer  *http.Server
	pprofEnabled bool
	pprofPort    int
}

// Config holds configuration for the proxy server
type Config struct {
	HTTPPort     int
	RuleEngine   rulesengine.Engine
	Auditor      audit.Auditor
	Logger       *slog.Logger
	TLSConfig    *tls.Config
	PprofEnabled bool
	PprofPort    int
	// InjectEngine, if non-nil, is used to evaluate whether outgoing
	// requests match configured inject targets for session correlation.
	// Built from config.SessionCorrelationConfig.InjectTargets via
	// NewInjectEngine using rulesengine.ParseAllowSpecs.
	InjectEngine *rulesengine.Engine
	// SessionID is the boundary session UUID injected as a header
	// on matching requests.
	SessionID string
	// ForwardTransport, if non-nil, is used when forwarding requests to
	// backend servers. Defaults to http.DefaultTransport when nil. Set in
	// tests to trust self-signed backend certificates.
	ForwardTransport http.RoundTripper
}

// NewProxyServer creates a new proxy server instance
func NewProxyServer(config Config) *Server {
	return &Server{
		ruleEngine:       config.RuleEngine,
		auditor:          config.Auditor,
		logger:           config.Logger,
		tlsConfig:        config.TLSConfig,
		httpPort:         config.HTTPPort,
		pprofEnabled:     config.PprofEnabled,
		pprofPort:        config.PprofPort,
		injectEngine:     config.InjectEngine,
		sessionID:        config.SessionID,
		forwardTransport: config.ForwardTransport,
	}
}

// NewInjectEngine builds a rule engine for session-correlation inject
// targets from sc, or returns nil when correlation is disabled or has no
// targets. The returned engine uses the same matching semantics as --allow
// rules so that inject-target evaluation is identical to allow-rule
// evaluation. sc is expected to have already been validated via
// config.ValidateSessionCorrelation.
func NewInjectEngine(sc config.SessionCorrelationConfig, logger *slog.Logger) (*rulesengine.Engine, error) {
	if !sc.Enabled || len(sc.InjectTargets) == 0 {
		return nil, nil
	}
	rules, err := rulesengine.ParseAllowSpecs(sc.InjectTargets)
	if err != nil {
		return nil, fmt.Errorf("parse inject targets: %w", err)
	}
	eng := rulesengine.NewRuleEngine(rules, logger)
	return &eng, nil
}

// Start starts the HTTP proxy server with TLS termination capability
func (p *Server) Start() error {
	if p.isStarted() {
		return nil
	}

	p.logger.Info("Starting HTTP proxy with TLS termination", "port", p.httpPort)

	// Start pprof server if enabled
	if p.pprofEnabled {
		p.pprofServer = &http.Server{
			Addr:    fmt.Sprintf(":%d", p.pprofPort),
			Handler: http.DefaultServeMux,
		}

		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", p.pprofPort))
		if err != nil {
			p.logger.Error("failed to listen on port for pprof server", "port", p.pprofPort, "error", err)
			return fmt.Errorf("failed to listen on port %v for pprof server: %v", p.pprofPort, err)
		}

		go func() {
			p.logger.Info("Serving pprof on existing listener", "port", p.pprofPort)
			if err := p.pprofServer.Serve(ln); err != nil && errors.Is(err, http.ErrServerClosed) {
				p.logger.Error("pprof server error", "error", err)
			}
		}()

	}

	var err error
	p.listener, err = net.Listen("tcp", fmt.Sprintf(":%d", p.httpPort))
	if err != nil {
		p.logger.Error("Failed to create HTTP listener", "error", err)
		return err
	}

	p.started.Store(true)

	// Start HTTP server with custom listener for TLS detection
	go func() {
		for {
			conn, err := p.listener.Accept()
			if err != nil && errors.Is(err, net.ErrClosed) && p.isStopped() {
				return
			}
			if err != nil {
				p.logger.Error("Failed to accept connection", "error", err)
				continue
			}

			// Handle connection with TLS detection
			go p.handleConnectionWithTLSDetection(conn)
		}
	}()

	return nil
}

// Stops proxy server
func (p *Server) Stop() error {
	if p.isStopped() {
		return nil
	}
	p.started.Store(false)

	if p.listener == nil {
		p.logger.Error("unexpected nil listener")
		return errors.New("unexpected nil listener")
	}

	err := p.listener.Close()
	if err != nil {
		p.logger.Error("Failed to close listener", "error", err)
		return err
	}

	// Close pprof server
	if p.pprofServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := p.pprofServer.Shutdown(ctx); err != nil {
			p.logger.Error("Failed to shutdown pprof server", "error", err)
		}
	}

	return nil
}

func (p *Server) isStarted() bool {
	return p.started.Load()
}

func (p *Server) isStopped() bool {
	return !p.started.Load()
}

func (p *Server) handleConnectionWithTLSDetection(conn net.Conn) {
	// Detect protocol using TLS handshake detection
	wrappedConn, isTLS, err := p.isTLSConnection(conn)
	if err != nil {
		p.logger.Error("Failed to check connection type", "error", err)

		err := conn.Close()
		if err != nil {
			p.logger.Error("Failed to close connection", "error", err)
		}
		return
	}
	if isTLS {
		p.logger.Debug("🔒 Detected TLS connection - handling as HTTPS")
		p.handleTLSConnection(wrappedConn)
	} else {
		p.logger.Debug("🌐 Detected HTTP connection")
		p.handleHTTPConnection(wrappedConn)
	}
}

func (p *Server) isTLSConnection(conn net.Conn) (net.Conn, bool, error) {
	// Read first byte to detect TLS
	buf := make([]byte, 1)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return nil, false, fmt.Errorf("failed to read first byte from connection: %v, read %v bytes", err, n)
	}

	connWrapper := &connectionWrapper{conn, buf, false}

	// TLS detection based on first byte:
	// 0x16 (22) = TLS Handshake
	// 0x17 (23) = TLS Application Data
	// 0x14 (20) = TLS Change Cipher Spec
	// 0x15 (21) = TLS Alert
	isTLS := buf[0] == 0x16 || buf[0] == 0x17 || buf[0] == 0x14 || buf[0] == 0x15

	if isTLS {
		p.logger.Debug("TLS detected", "first byte", buf[0])
	}

	return connWrapper, isTLS, nil
}

func (p *Server) handleHTTPConnection(conn net.Conn) {
	defer func() {
		err := conn.Close()
		if err != nil && !errors.Is(err, net.ErrClosed) {
			p.logger.Error("Failed to close connection", "error", err)
		}
	}()

	// Read HTTP request
	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		p.logger.Error("Failed to read HTTP request", "error", err)
		return
	}

	if req.Method == http.MethodConnect {
		p.handleCONNECT(conn, req)
		return
	}

	p.logger.Debug("🌐 HTTP Request", "method", req.Method, "url", req.URL.String())
	p.processHTTPRequest(conn, reader, req, false)
}

func (p *Server) handleTLSConnection(conn net.Conn) {
	// Create TLS connection
	tlsConn := tls.Server(conn, p.tlsConfig)

	defer func() {
		err := tlsConn.Close()
		if err != nil && !errors.Is(err, net.ErrClosed) {
			p.logger.Error("Failed to close TLS connection", "error", err)
		}
	}()

	// Perform TLS handshake
	if err := tlsConn.Handshake(); err != nil {
		p.logger.Error("TLS handshake failed", "error", err)
		return
	}

	p.logger.Debug("✅ TLS handshake successful")

	// Read HTTP request over TLS
	reader := bufio.NewReader(tlsConn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		p.logger.Error("Failed to read HTTPS request", "error", err)
		return
	}

	p.logger.Debug("🔒 HTTPS Request", "method", req.Method, "url", req.URL.String())
	p.processHTTPRequest(tlsConn, reader, req, true)
}

// processHTTPRequest evaluates one request against the policy, audits the
// decision, and either blocks it or forwards it. clientReader is the
// buffered reader the request was parsed from; it may already hold bytes
// the client sent after the request headers, which matters for protocol
// upgrades.
func (p *Server) processHTTPRequest(conn net.Conn, clientReader *bufio.Reader, req *http.Request, https bool) {
	p.logger.Debug("   Host", "host", req.Host)
	p.logger.Debug("   User-Agent", "user-agent", req.Header.Get("User-Agent"))

	// Construct fully qualified URL for rule evaluation and auditing.
	// In boundary's normal transparent proxy operation, req.URL only contains
	// the path since clients don't know they're going through a proxy.
	// When clients explicitly configure a proxy, req.URL contains the full URL.
	fullURL := req.URL.String()
	if req.URL.Scheme == "" {
		scheme := "http"
		if https {
			scheme = "https"
		}
		fullURL = scheme + "://" + req.Host + fullURL
	}

	result := p.ruleEngine.Evaluate(req.Method, fullURL)

	seqNum := p.seqCounter.Next()

	p.auditor.AuditRequest(audit.Request{
		Method:         req.Method,
		URL:            fullURL,
		Host:           req.Host,
		Allowed:        result.Allowed,
		Rule:           result.Rule,
		SequenceNumber: seqNum,
	})

	if !result.Allowed {
		p.writeBlockedResponse(conn, req)
		return
	}

	// Protocol upgrades (WebSocket, DERP) become a bidirectional byte
	// stream after the handshake, which the request/response forwarder
	// below cannot carry.
	if isUpgradeRequest(req) {
		p.forwardUpgrade(conn, clientReader, req, https, seqNum)
		return
	}

	// Forward request to destination
	p.forwardRequest(conn, req, https, seqNum)
}

// isUpgradeRequest reports whether req asks the server to switch protocols
// (RFC 9110 section 7.8): it carries an Upgrade header and lists "upgrade"
// in Connection.
func isUpgradeRequest(req *http.Request) bool {
	if req.Header.Get("Upgrade") == "" {
		return false
	}
	for _, v := range req.Header.Values("Connection") {
		for _, token := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				return true
			}
		}
	}
	return false
}

// upstreamTLSConfig returns the TLS config for a direct connection to an
// upstream server. It reuses the forward transport's TLS settings when
// one is configured, so tests can trust self-signed backends the same way
// they do for ordinary requests.
func (p *Server) upstreamTLSConfig(serverName string) *tls.Config {
	var cfg *tls.Config
	if t, ok := p.forwardTransport.(*http.Transport); ok && t.TLSClientConfig != nil {
		cfg = t.TLSClientConfig.Clone()
	} else {
		cfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	cfg.ServerName = serverName
	// The client speaks HTTP/1.1 to us; keep the upstream on HTTP/1.1 so
	// the handshake and the upgraded stream can be relayed byte for byte.
	cfg.NextProtos = []string{"http/1.1"}
	return cfg
}

// forwardUpgrade relays a protocol upgrade. It dials the upstream itself,
// writes the handshake request with its Connection and Upgrade headers
// intact, and reads the response. On 101 Switching Protocols it returns
// the response to the client and copies bytes in both directions until
// either side closes. Any other status is returned to the client as a
// normal response. Only the handshake is audited; the stream that follows
// is opaque to the policy engine.
func (p *Server) forwardUpgrade(conn net.Conn, clientReader *bufio.Reader, req *http.Request, https bool, seqNum int32) {
	host := req.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		if https {
			host = net.JoinHostPort(host, "443")
		} else {
			host = net.JoinHostPort(host, "80")
		}
	}
	serverName, _, _ := net.SplitHostPort(host)

	upstream, err := net.DialTimeout("tcp", host, 30*time.Second)
	if err != nil {
		p.logger.Error("Failed to dial upstream for upgrade", "host", host, "error", err)
		p.writeUpgradeFailure(conn, req, http.StatusBadGateway)
		return
	}
	defer func() {
		if err := upstream.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			p.logger.Debug("Failed to close upstream connection", "error", err)
		}
	}()
	if https {
		tlsUpstream := tls.Client(upstream, p.upstreamTLSConfig(serverName))
		if err := tlsUpstream.Handshake(); err != nil {
			p.logger.Error("TLS handshake with upstream failed for upgrade", "host", host, "error", err)
			p.writeUpgradeFailure(conn, req, http.StatusBadGateway)
			return
		}
		upstream = tlsUpstream
	}

	scheme := "http"
	if https {
		scheme = "https"
	}
	outReq := req.Clone(context.Background())
	outReq.URL = &url.URL{
		Scheme:   scheme,
		Host:     req.Host,
		Path:     req.URL.Path,
		RawPath:  req.URL.RawPath,
		RawQuery: req.URL.RawQuery,
	}
	outReq.RequestURI = ""
	outReq.Header.Del("Proxy-Connection")
	if p.shouldInjectHeaders(outReq.URL.String()) {
		outReq.Header.Set(config.SessionIDHeaderName, p.sessionID)
		outReq.Header.Set(config.SequenceNumberHeaderName, strconv.Itoa(int(seqNum)))
	}
	if err := outReq.Write(upstream); err != nil {
		p.logger.Error("Failed to write upgrade request to upstream", "host", host, "error", err)
		p.writeUpgradeFailure(conn, req, http.StatusBadGateway)
		return
	}

	upstreamReader := bufio.NewReader(upstream)
	resp, err := http.ReadResponse(upstreamReader, outReq)
	if err != nil {
		p.logger.Error("Failed to read upgrade response from upstream", "host", host, "error", err)
		p.writeUpgradeFailure(conn, req, http.StatusBadGateway)
		return
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		// The server declined the upgrade; hand its answer back as-is.
		p.logger.Debug("Upstream declined upgrade", "host", host, "status", resp.Status)
		defer resp.Body.Close() //nolint:errcheck
		resp.Proto = "HTTP/1.1"
		resp.ProtoMajor = 1
		resp.ProtoMinor = 1
		if err := resp.Write(conn); err != nil {
			p.logger.Error("Failed to write declined upgrade response", "host", host, "error", err)
		}
		return
	}

	if err := resp.Write(conn); err != nil {
		p.logger.Error("Failed to write 101 response to client", "host", host, "error", err)
		return
	}
	p.logger.Debug("Upgrade established, relaying stream", "host", host, "protocol", resp.Header.Get("Upgrade"))

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, clientReader)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(conn, upstreamReader)
		done <- struct{}{}
	}()
	// When either direction ends, close both sides so the other copy
	// returns; the deferred close and the caller's close handle cleanup.
	<-done
	_ = upstream.Close()
	_ = conn.Close()
	<-done
	p.logger.Debug("Upgrade stream closed", "host", host)
}

// writeUpgradeFailure answers the client when the upstream could not be
// reached or did not answer the handshake.
func (p *Server) writeUpgradeFailure(conn net.Conn, req *http.Request, status int) {
	resp := &http.Response{
		StatusCode:    status,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(http.StatusText(status))),
		ContentLength: int64(len(http.StatusText(status))),
		Request:       req,
	}
	resp.Header.Set("Content-Type", "text/plain")
	if err := resp.Write(conn); err != nil {
		p.logger.Error("Failed to write upgrade failure response", "error", err)
	}
}

// shouldInjectHeaders reports whether the request URL matches any
// configured inject target. Inject targets are evaluated using the same
// rulesengine matching as --allow rules so that domain/path semantics
// are unified. When session correlation is disabled or no targets match
// it returns false.
func (p *Server) shouldInjectHeaders(fullURL string) bool {
	if p.injectEngine == nil {
		return false
	}
	// Inject targets do not restrict by HTTP method, so we pass an empty
	// method. Rules without a method pattern match all methods.
	return p.injectEngine.Evaluate("", fullURL).Allowed
}

func (p *Server) forwardRequest(conn net.Conn, req *http.Request, https bool, seqNum int32) {
	// Create HTTP client
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
		Transport: p.forwardTransport, // nil → http.DefaultTransport
	}

	scheme := "http"
	if https {
		scheme = "https"
	}

	// RawPath preserves the original percent-encoding (e.g. %2F in scoped
	// npm package names like /@sentry%2Fbun) so url.URL.String() doesn't
	// re-encode reserved characters as their literal form.
	targetURL := &url.URL{
		Scheme:   scheme,
		Host:     req.Host,
		Path:     req.URL.Path,
		RawPath:  req.URL.RawPath,
		RawQuery: req.URL.RawQuery,
	}

	var body = req.Body
	if req.Method == http.MethodGet || req.Method == http.MethodHead {
		body = nil
	}
	newReq, err := http.NewRequest(req.Method, targetURL.String(), body)
	if err != nil {
		p.logger.Error("can't create http request", "error", err)
		return
	}

	// Copy headers
	for name, values := range req.Header {
		// Skip connection-specific headers
		if strings.ToLower(name) == "connection" || strings.ToLower(name) == "proxy-connection" {
			continue
		}
		for _, value := range values {
			newReq.Header.Add(name, value)
		}
	}

	if p.shouldInjectHeaders(targetURL.String()) {
		newReq.Header.Set(config.SessionIDHeaderName, p.sessionID)
		newReq.Header.Set(config.SequenceNumberHeaderName, strconv.Itoa(int(seqNum)))
	}

	// Make request to destination
	resp, err := client.Do(newReq)
	if err != nil {
		p.logger.Error("Failed to forward HTTPS request", "error", err)
		return
	}

	p.logger.Debug("🔒 HTTPS Response", "status code", resp.StatusCode, "status", resp.Status)

	p.logger.Debug("Forwarded Request",
		"method", newReq.Method,
		"host", newReq.Host,
		"URL", newReq.URL,
	)

	// Read the body and explicitly set Content-Length header, otherwise client can hung up on the request.
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		p.logger.Error("can't read response body", "error", err)
		return
	}
	resp.Header.Add("Content-Length", strconv.Itoa(len(bodyBytes)))
	resp.ContentLength = int64(len(bodyBytes))
	err = resp.Body.Close()
	if err != nil {
		p.logger.Error("Failed to close HTTP response body", "error", err)
		return
	}
	resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// The downstream client (Claude) always communicates over HTTP/1.1.
	// However, Go's default HTTP client may negotiate an HTTP/2 connection
	// with the upstream server via ALPN during TLS handshake.
	// This can cause the response's Proto field to be set to "HTTP/2.0",
	// which would produce an invalid response for an HTTP/1.1 client.
	// To prevent this mismatch, we explicitly normalize the response
	// to HTTP/1.1 before writing it back to the client.
	resp.Proto = "HTTP/1.1"
	resp.ProtoMajor = 1
	resp.ProtoMinor = 1

	// Copy response back to client
	err = resp.Write(conn)
	if err != nil {
		p.logger.Error("Failed to forward back HTTP response",
			"error", err,
			"host", req.Host,
			"method", req.Method,
			//"bodyBytes", string(bodyBytes),
		)
		return
	}

	p.logger.Debug("Successfully wrote to connection")
}

func (p *Server) writeBlockedResponse(conn net.Conn, req *http.Request) {
	// Create a response object
	resp := &http.Response{
		Status:        "403 Forbidden",
		StatusCode:    http.StatusForbidden,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          nil,
		ContentLength: 0,
	}

	// Set headers
	resp.Header.Set("Content-Type", "text/plain")

	// Create the response body
	host := req.URL.Host
	if host == "" {
		host = req.Host
	}

	body := fmt.Sprintf(`🚫 Request Blocked by Boundary

Request: %s %s
Host: %s

To allow this request, restart boundary with:
  --allow "domain=%s"                    # Allow all methods to this host
  --allow "method=%s domain=%s"          # Allow only %s requests to this host

For more help: https://github.com/coder/boundary
`,
		req.Method, req.URL.Path, host, host, req.Method, host, req.Method)

	resp.Body = io.NopCloser(strings.NewReader(body))
	resp.ContentLength = int64(len(body))

	// Copy response back to client
	err := resp.Write(conn)
	if err != nil {
		p.logger.Error("Failed to write blocker response", "error", err)
		return
	}

	p.logger.Debug("Successfully wrote to connection")
}

// connectionWrapper lets us "unread" the peeked byte
type connectionWrapper struct {
	net.Conn
	buf     []byte
	bufUsed bool
}

func (c *connectionWrapper) Read(p []byte) (int, error) {
	if !c.bufUsed && len(c.buf) > 0 {
		n := copy(p, c.buf)
		c.bufUsed = true
		return n, nil
	}
	return c.Conn.Read(p)
}
