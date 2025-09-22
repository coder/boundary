package proxy

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/coder/boundary/audit"
	"github.com/coder/boundary/rules"
)

// Server handles HTTP and HTTPS requests with rule-based filtering
type Server struct {
	ruleEngine rules.Evaluator
	auditor    audit.Auditor
	logger     *slog.Logger
	tlsConfig  *tls.Config
	httpPort   int
	started    atomic.Bool

	listener net.Listener
}

// Config holds configuration for the proxy server
type Config struct {
	HTTPPort   int
	RuleEngine rules.Evaluator
	Auditor    audit.Auditor
	Logger     *slog.Logger
	TLSConfig  *tls.Config
}

// NewProxyServer creates a new proxy server instance
func NewProxyServer(config Config) *Server {
	return &Server{
		ruleEngine: config.RuleEngine,
		auditor:    config.Auditor,
		logger:     config.Logger,
		tlsConfig:  config.TLSConfig,
		httpPort:   config.HTTPPort,
	}
}

// Start starts the HTTP proxy server with TLS termination capability
func (p *Server) Start() error {
	if p.isStarted() {
		return nil
	}

	p.logger.Info("Starting HTTP proxy with TLS termination", "port", p.httpPort)
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

	return nil
}

func (p *Server) isStarted() bool {
	return p.started.Load()
}

func (p *Server) isStopped() bool {
	return !p.started.Load()
}

// handleHTTP handles regular HTTP requests and CONNECT tunneling
func (p *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	p.logger.Debug("handleHTTP called", "method", r.Method, "url", r.URL.String(), "host", r.Host)

	// Handle CONNECT method for HTTPS tunneling
	if r.Method == "CONNECT" {
		p.handleConnect(w, r)
		return
	}

	// Ensure URL is fully qualified
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}
	if r.URL.Scheme == "" {
		r.URL.Scheme = "http"
	}

	// Check if request should be allowed
	result := p.ruleEngine.Evaluate(r.Method, r.URL.String())

	// Audit the request
	p.auditor.AuditRequest(audit.Request{
		Method:  r.Method,
		URL:     r.URL.String(),
		Allowed: result.Allowed,
		Rule:    result.Rule,
	})

	if !result.Allowed {
		p.writeBlockedResponse(w, r)
		return
	}

	// Forward regular HTTP request
	p.forwardRequest(w, r, false)
}

// forwardRequest forwards a regular HTTP request
func (p *Server) forwardRequest(w http.ResponseWriter, r *http.Request, https bool) {
	p.logger.Debug("forwardHTTPRequest called", "method", r.Method, "url", r.URL.String(), "host", r.Host)

	s := "http"
	if https {
		s = "https"
	}
	// Create a new request to the target server
	targetURL := &url.URL{
		Scheme:   s,
		Host:     r.Host,
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}

	p.logger.Debug("Target URL constructed", "target", targetURL.String())

	// Create HTTP client with very short timeout for debugging
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	// Create new request
	req, err := http.NewRequest(r.Method, targetURL.String(), r.Body)
	if err != nil {
		p.logger.Error("Failed to create forward request", "error", err)
		http.Error(w, fmt.Sprintf("Failed to create request: %v", err), http.StatusInternalServerError)
		return
	}

	// Copy headers
	for name, values := range r.Header {
		// Skip connection-specific headers
		if strings.ToLower(name) == "connection" || strings.ToLower(name) == "proxy-connection" {
			continue
		}
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}

	p.logger.Debug("About to make HTTP request", "target", targetURL.String())
	resp, err := client.Do(req)
	if err != nil {
		p.logger.Error("Failed to make forward request", "error", err, "target", targetURL.String(), "error_type", fmt.Sprintf("%T", err))
		http.Error(w, fmt.Sprintf("Failed to make request: %v", err), http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	p.logger.Debug("Received response", "status", resp.StatusCode, "target", targetURL.String())

	// Copy response headers (except connection-specific ones)
	for name, values := range resp.Header {
		if strings.ToLower(name) == "connection" || strings.ToLower(name) == "transfer-encoding" {
			continue
		}
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}

	// Copy status code
	w.WriteHeader(resp.StatusCode)

	// Copy response body
	bytesWritten, copyErr := io.Copy(w, resp.Body)
	if copyErr != nil {
		p.logger.Error("Error copying response body", "error", copyErr, "bytes_written", bytesWritten)
		http.Error(w, "Failed to copy response", http.StatusBadGateway)
	} else {
		p.logger.Debug("Successfully forwarded HTTP response", "bytes_written", bytesWritten, "status", resp.StatusCode)
	}

	// Ensure response is flushed
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	p.logger.Debug("forwardHTTPRequest completed")
}

// writeBlockedResponse writes a blocked response
func (p *Server) writeBlockedResponse(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusForbidden)

	// Extract host from URL for cleaner display
	host := r.URL.Host
	if host == "" {
		host = r.Host
	}

	_, _ = fmt.Fprintf(w, `🚫 Request Blocked by Boundary

Request: %s %s
Host: %s

To allow this request, restart boundary with:
  --allow "domain=%s"                    # Allow all methods to this host
  --allow "method=%s domain=%s"          # Allow only %s requests to this host

For more help: https://github.com/coder/boundary
`,
		r.Method, r.URL.Path, host, host, r.Method, host, r.Method)
}

// handleConnect handles CONNECT requests for HTTPS tunneling with TLS termination
func (p *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	// Extract hostname from the CONNECT request
	hostname := r.URL.Hostname()
	if hostname == "" {
		// Fallback to Host header parsing
		host := r.URL.Host
		if host == "" {
			host = r.Host
		}
		if h, _, err := net.SplitHostPort(host); err == nil {
			hostname = h
		} else {
			hostname = host
		}
	}

	if hostname == "" {
		http.Error(w, "Invalid CONNECT request: no hostname", http.StatusBadRequest)
		return
	}

	// Allow all CONNECT requests - we'll evaluate rules on the decrypted HTTPS content
	p.logger.Debug("Establishing CONNECT tunnel with TLS termination", "hostname", hostname)

	// Hijack the connection to handle TLS manually
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	// Hijack the underlying connection
	conn, _, err := hijacker.Hijack()
	if err != nil {
		p.logger.Error("Failed to hijack connection", "error", err)
		return
	}
	defer func() {
		err := conn.Close()
		if err != nil {
			p.logger.Error("Failed to close connection", "error", err)
		}
	}()

	// Send 200 Connection established response manually
	_, err = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	if err != nil {
		p.logger.Error("Failed to send CONNECT response", "error", err)
		return
	}

	// Perform TLS handshake with the client using our certificates
	p.logger.Debug("Starting TLS handshake", "hostname", hostname)

	// Create TLS config that forces HTTP/1.1 (disable HTTP/2 ALPN)
	tlsConfig := p.tlsConfig.Clone()
	tlsConfig.NextProtos = []string{"http/1.1"}

	tlsConn := tls.Server(conn, tlsConfig)
	err = tlsConn.Handshake()
	if err != nil {
		p.logger.Error("TLS handshake failed", "hostname", hostname, "error", err)
		return
	}
	p.logger.Debug("TLS handshake successful", "hostname", hostname)

	// Log connection state after handshake
	state := tlsConn.ConnectionState()
	p.logger.Debug("TLS connection established", "hostname", hostname, "version", state.Version, "cipher_suite", state.CipherSuite, "negotiated_protocol", state.NegotiatedProtocol)

	// Now we have a TLS connection - handle HTTPS requests
	p.logger.Debug("Starting HTTPS request handling", "hostname", hostname)
	p.handleTLSConnection(tlsConn, hostname)
	p.logger.Debug("HTTPS request handling completed", "hostname", hostname)
}

// handleTLSConnection processes decrypted HTTPS requests over the TLS connection with streaming support
func (p *Server) handleTLSConnection(tlsConn *tls.Conn, hostname string) {
	p.logger.Debug("Creating streaming HTTP handler for TLS connection", "hostname", hostname)

	// Use streaming HTTP parsing instead of ReadRequest
	bufReader := bufio.NewReader(tlsConn)
	for {
		// Parse HTTP request headers incrementally
		req, err := p.parseHTTPRequestHeaders(bufReader, hostname)
		if err != nil {
			if err == io.EOF {
				p.logger.Debug("TLS connection closed by client", "hostname", hostname)
			} else {
				p.logger.Debug("Failed to parse HTTP request headers", "hostname", hostname, "error", err)
			}
			break
		}

		p.logger.Debug("Processing streaming HTTPS request", "hostname", hostname, "method", req.Method, "path", req.URL.Path)

		// Handle CONNECT method for HTTPS tunneling
		if req.Method == "CONNECT" {
			p.handleConnectStreaming(tlsConn, req, hostname)
			return // CONNECT takes over the entire connection
		}

		// Check if request should be allowed (based on headers only)
		fullURL := p.constructFullURL(req, hostname)
		result := p.ruleEngine.Evaluate(req.Method, fullURL)

		// Audit the request
		p.auditor.AuditRequest(audit.Request{
			Method:  req.Method,
			URL:     fullURL,
			Allowed: result.Allowed,
			Rule:    result.Rule,
		})

		if !result.Allowed {
			p.writeBlockedResponseStreaming(tlsConn, req)
			continue
		}

		// Stream the request to target server
		err = p.streamRequestToTarget(tlsConn, bufReader, req, hostname)
		if err != nil {
			p.logger.Debug("Error streaming request", "hostname", hostname, "error", err)
			break
		}
	}

	p.logger.Debug("TLS connection handling completed", "hostname", hostname)
}

// handleDecryptedHTTPS handles decrypted HTTPS requests and applies rules
func (p *Server) handleDecryptedHTTPS(w http.ResponseWriter, r *http.Request) {
	// Handle CONNECT method for HTTPS tunneling
	if r.Method == "CONNECT" {
		p.handleConnect(w, r)
		return
	}

	fullURL := r.URL.String()
	if r.URL.Host == "" {
		// Fallback: construct URL from Host header
		fullURL = fmt.Sprintf("https://%s%s", r.Host, r.URL.Path)
		if r.URL.RawQuery != "" {
			fullURL += "?" + r.URL.RawQuery
		}
	}
	// Check if request should be allowed
	result := p.ruleEngine.Evaluate(r.Method, fullURL)

	// Audit the request
	p.auditor.AuditRequest(audit.Request{
		Method:  r.Method,
		URL:     fullURL,
		Allowed: result.Allowed,
		Rule:    result.Rule,
	})

	if !result.Allowed {
		p.writeBlockedResponse(w, r)
		return
	}

	// Forward the HTTPS request (now handled same as HTTP after TLS termination)
	p.forwardRequest(w, r, true)
}

// handleConnectionWithTLSDetection detects TLS vs HTTP and handles appropriately
func (p *Server) handleConnectionWithTLSDetection(conn net.Conn) {
	defer func() {
		err := conn.Close()
		if err != nil {
			p.logger.Error("Failed to close connection", "error", err)
		}
	}()

	// Peek at first byte to detect protocol
	buf := make([]byte, 1)
	_, err := conn.Read(buf)
	if err != nil {
		p.logger.Debug("Failed to read first byte from connection", "error", err)
		return
	}

	// Create connection wrapper that can "unread" the peeked byte
	connWrapper := &connectionWrapper{conn, buf, false}

	// TLS handshake starts with 0x16 (TLS Content Type: Handshake)
	if buf[0] == 0x16 {
		p.logger.Debug("Detected TLS handshake, performing TLS termination")
		// Perform TLS handshake
		tlsConn := tls.Server(connWrapper, p.tlsConfig)
		err := tlsConn.Handshake()
		if err != nil {
			p.logger.Debug("TLS handshake failed", "error", err)
			return
		}
		p.logger.Debug("TLS handshake successful")
		// Use HTTP server with TLS connection
		listener := newSingleConnectionListener(tlsConn)
		defer func() {
			err := listener.Close()
			if err != nil {
				p.logger.Error("Failed to close connection", "error", err)
			}
		}()
		err = http.Serve(listener, http.HandlerFunc(p.handleDecryptedHTTPS))
		p.logger.Debug("http.Serve completed for HTTPS", "error", err)
	} else {
		p.logger.Debug("Detected HTTP request, handling normally")
		// Use HTTP server with regular connection
		p.logger.Debug("About to call http.Serve for HTTP connection")
		listener := newSingleConnectionListener(connWrapper)
		defer func() {
			err := listener.Close()
			if err != nil {
				p.logger.Error("Failed to close connection", "error", err)
			}
		}()
		err = http.Serve(listener, http.HandlerFunc(p.handleHTTP))
		p.logger.Debug("http.Serve completed", "error", err)
	}
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

// singleConnectionListener wraps a single connection into a net.Listener
type singleConnectionListener struct {
	conn   net.Conn
	used   bool
	closed chan struct{}
	mu     sync.Mutex
}

func newSingleConnectionListener(conn net.Conn) *singleConnectionListener {
	return &singleConnectionListener{
		conn:   conn,
		closed: make(chan struct{}),
	}
}

func (sl *singleConnectionListener) Accept() (net.Conn, error) {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	if sl.used || sl.conn == nil {
		// Wait for close signal
		<-sl.closed
		return nil, io.EOF
	}
	sl.used = true
	return sl.conn, nil
}

func (sl *singleConnectionListener) Close() error {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	select {
	case <-sl.closed:
		// Already closed
	default:
		close(sl.closed)
	}

	if sl.conn != nil {
		err := sl.conn.Close()
		if err != nil {
			return fmt.Errorf("failed to close connection: %w", err)
		}
		sl.conn = nil
	}
	return nil
}

func (sl *singleConnectionListener) Addr() net.Addr {
	if sl.conn == nil {
		return nil
	}
	return sl.conn.LocalAddr()
}

// parseHTTPRequestHeaders parses HTTP request headers incrementally without reading the body
func (p *Server) parseHTTPRequestHeaders(bufReader *bufio.Reader, hostname string) (*http.Request, error) {
	// Read the request line (e.g., "GET /path HTTP/1.1")
	requestLine, _, err := bufReader.ReadLine()
	if err != nil {
		return nil, err
	}

	// Parse request line
	parts := strings.Fields(string(requestLine))
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid request line: %s", requestLine)
	}

	method := parts[0]
	requestURI := parts[1]
	proto := parts[2]

	// Parse URL
	var url *url.URL
	if strings.HasPrefix(requestURI, "http://") || strings.HasPrefix(requestURI, "https://") {
		url, err = url.Parse(requestURI)
	} else {
		// Relative URL, construct with hostname
		url, err = url.Parse("https://" + hostname + requestURI)
	}
	if err != nil {
		return nil, fmt.Errorf("invalid request URI: %s", requestURI)
	}

	// Read headers
	headers := make(http.Header)
	for {
		headerLine, _, err := bufReader.ReadLine()
		if err != nil {
			return nil, err
		}

		// Empty line indicates end of headers
		if len(headerLine) == 0 {
			break
		}

		// Parse header
		headerStr := string(headerLine)
		colonIdx := strings.Index(headerStr, ":")
		if colonIdx == -1 {
			continue // Skip malformed headers
		}

		headerName := strings.TrimSpace(headerStr[:colonIdx])
		headerValue := strings.TrimSpace(headerStr[colonIdx+1:])
		headers.Add(headerName, headerValue)
	}

	// Create request object (without body)
	req := &http.Request{
		Method: method,
		URL:    url,
		Proto:  proto,
		Header: headers,
		Host:   url.Host,
		// Note: Body is intentionally nil - we'll stream it separately
	}

	return req, nil
}

// constructFullURL builds the full URL from request and hostname
func (p *Server) constructFullURL(req *http.Request, hostname string) string {
	if req.URL.Host == "" {
		req.URL.Host = hostname
	}
	if req.URL.Scheme == "" {
		req.URL.Scheme = "https"
	}
	return req.URL.String()
}

// writeBlockedResponseStreaming writes a blocked response directly to the TLS connection
func (p *Server) writeBlockedResponseStreaming(tlsConn *tls.Conn, req *http.Request) {
	response := fmt.Sprintf("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n🚫 Request Blocked by Boundary\n\nRequest: %s %s\nHost: %s\n\nTo allow this request, restart boundary with:\n  --allow \"domain=%s\"\n",
		req.Method, req.URL.Path, req.Host, req.Host)
	_, _ = tlsConn.Write([]byte(response))
}

// streamRequestToTarget streams the HTTP request (including body) to the target server
func (p *Server) streamRequestToTarget(clientConn *tls.Conn, bufReader *bufio.Reader, req *http.Request, hostname string) error {
	// Connect to target server
	targetConn, err := tls.Dial("tcp", hostname+":443", &tls.Config{ServerName: hostname})
	if err != nil {
		return fmt.Errorf("failed to connect to target %s: %v", hostname, err)
	}
	defer func() {
		err := targetConn.Close()
		if err != nil {
			p.logger.Error("Failed to close target connection", "error", err)
		}
	}()

	// Send HTTP request headers to target
	reqLine := fmt.Sprintf("%s %s %s\r\n", req.Method, req.URL.RequestURI(), req.Proto)
	_, err = targetConn.Write([]byte(reqLine))
	if err != nil {
		return fmt.Errorf("failed to write request line to target: %v", err)
	}

	// Send headers
	for name, values := range req.Header {
		for _, value := range values {
			headerLine := fmt.Sprintf("%s: %s\r\n", name, value)
			_, err = targetConn.Write([]byte(headerLine))
			if err != nil {
				return fmt.Errorf("failed to write header to target: %v", err)
			}
		}
	}
	_, err = targetConn.Write([]byte("\r\n")) // End of headers
	if err != nil {
		return fmt.Errorf("failed to write headers to target: %v", err)
	}

	// Stream request body and response bidirectionally
	go func() {
		// Stream request body: client -> target
		_, err := io.Copy(targetConn, bufReader)
		if err != nil {
			p.logger.Error("Error copying request body to target", "error", err)
		}
	}()

	// Stream response: target -> client
	_, err = io.Copy(clientConn, targetConn)
	if err != nil {
		p.logger.Error("Error copying response from target to client", "error", err)
	}

	return nil
}

// handleConnectStreaming handles CONNECT requests with streaming TLS termination
func (p *Server) handleConnectStreaming(tlsConn *tls.Conn, req *http.Request, hostname string) {
	p.logger.Debug("Handling CONNECT request with streaming", "hostname", hostname)

	// For CONNECT, we need to establish a tunnel but still maintain TLS termination
	// This is the tricky part - we're already inside a TLS connection from the client
	// The client is asking us to CONNECT to another server, but we want to intercept that too

	// Send CONNECT response
	response := "HTTP/1.1 200 Connection established\r\n\r\n"
	_, err := tlsConn.Write([]byte(response))
	if err != nil {
		p.logger.Error("Failed to send CONNECT response", "error", err)
		return
	}

	// Now the client will try to do TLS handshake for the target server
	// But we want to intercept and terminate it
	// This means we need to do another level of TLS termination

	// For now, let's create a simple tunnel and log that we're not inspecting
	p.logger.Warn("CONNECT tunnel established - content not inspected", "hostname", hostname)

	// Create connection to real target
	targetConn, err := net.Dial("tcp", req.Host)
	if err != nil {
		p.logger.Error("Failed to connect to CONNECT target", "target", req.Host, "error", err)
		return
	}
	defer func() { _ = targetConn.Close() }()

	// Bidirectional copy
	go func() {
		_, err := io.Copy(targetConn, tlsConn)
		if err != nil {
			p.logger.Error("Error copying from client to target", "error", err)
		}
	}()
	_, err = io.Copy(tlsConn, targetConn)
	if err != nil {
		p.logger.Error("Error copying from target to client", "error", err)
	}
	p.logger.Debug("CONNECT tunnel closed", "hostname", hostname)
}
