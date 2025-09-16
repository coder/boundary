package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"

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

	httpServer *http.Server
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
func (p *Server) Start(ctx context.Context) error {
	// Create HTTP server with TLS termination capability
	p.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", p.httpPort),
		Handler: http.HandlerFunc(p.handleHTTPWithTLSTermination),
	}

	// Start HTTP server with custom listener for TLS detection
	go func() {
		p.logger.Info("Starting HTTP proxy with TLS termination", "port", p.httpPort)
		listener, err := net.Listen("tcp", fmt.Sprintf(":%d", p.httpPort))
		if err != nil {
			p.logger.Error("Failed to create HTTP listener", "error", err)
			return
		}

		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					listener.Close()
					return
				default:
					p.logger.Error("Failed to accept connection", "error", err)
					continue
				}
			}

			// Handle connection with TLS detection
			go p.handleConnectionWithTLSDetection(conn)
		}
	}()

	// Wait for context cancellation
	<-ctx.Done()
	return p.Stop()
}

// Stops proxy server
func (p *Server) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var httpErr error
	if p.httpServer != nil {
		httpErr = p.httpServer.Shutdown(ctx)
	}

	if httpErr != nil {
		return httpErr
	}
	return nil
}

// handleHTTP handles regular HTTP requests and CONNECT tunneling
func (p *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	p.logger.Debug("handleHTTP called", "method", r.Method, "url", r.URL.String(), "host", r.Host)

	// Handle CONNECT method for HTTPS tunneling
	if r.Method == "CONNECT" {
		p.handleConnect(w, r)
		return
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
	defer resp.Body.Close()

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

	fmt.Fprintf(w, `🚫 Request Blocked by Boundary

Request: %s %s
Host: %s

To allow this request, restart boundary with:
  --allow "%s"                    # Allow all methods to this host
  --allow "%s %s"          # Allow only %s requests to this host

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
	defer conn.Close()

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

	// Now we have a TLS connection - handle HTTPS requests
	p.logger.Debug("Starting HTTPS request handling", "hostname", hostname)
	p.handleTLSConnection(tlsConn, hostname)
	p.logger.Debug("HTTPS request handling completed", "hostname", hostname)
}

// handleTLSConnection processes decrypted HTTPS requests over the TLS connection
func (p *Server) handleTLSConnection(tlsConn *tls.Conn, hostname string) {
	p.logger.Debug("Creating HTTP server for TLS connection", "hostname", hostname)

	// Use ReadRequest to manually read HTTP requests from the TLS connection
	bufReader := bufio.NewReader(tlsConn)
	for {
		// Read HTTP request from TLS connection
		req, err := http.ReadRequest(bufReader)
		if err != nil {
			if err == io.EOF {
				p.logger.Debug("TLS connection closed by client", "hostname", hostname)
			} else {
				p.logger.Debug("Failed to read HTTP request", "hostname", hostname, "error", err)
			}
			break
		}

		p.logger.Debug("Processing decrypted HTTPS request", "hostname", hostname, "method", req.Method, "path", req.URL.Path)

		// Set the hostname and scheme if not already set
		if req.URL.Host == "" {
			req.URL.Host = hostname
		}
		if req.URL.Scheme == "" {
			req.URL.Scheme = "https"
		}

		// Create a response recorder to capture the response
		recorder := httptest.NewRecorder()

		// Process the HTTPS request
		p.handleDecryptedHTTPS(recorder, req)

		// Write the response back to the TLS connection
		resp := recorder.Result()
		err = resp.Write(tlsConn)
		if err != nil {
			p.logger.Debug("Failed to write response", "hostname", hostname, "error", err)
			break
		}
	}

	p.logger.Debug("TLS connection handling completed", "hostname", hostname)
}

// handleDecryptedHTTPS handles decrypted HTTPS requests and applies rules
func (p *Server) handleDecryptedHTTPS(w http.ResponseWriter, r *http.Request) {
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
	defer conn.Close()

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
		defer listener.Close()
		err = http.Serve(listener, http.HandlerFunc(p.handleDecryptedHTTPS))
		p.logger.Debug("http.Serve completed for HTTPS", "error", err)
	} else {
		p.logger.Debug("Detected HTTP request, handling normally")
		// Use HTTP server with regular connection
		p.logger.Debug("About to call http.Serve for HTTP connection")
		listener := newSingleConnectionListener(connWrapper)
		defer listener.Close()
		err = http.Serve(listener, http.HandlerFunc(p.handleHTTP))
		p.logger.Debug("http.Serve completed", "error", err)
	}
}

// handleHTTPWithTLSTermination is the main handler (currently just delegates to regular HTTP)
func (p *Server) handleHTTPWithTLSTermination(w http.ResponseWriter, r *http.Request) {
	// This handler is not used when we do custom connection handling
	// All traffic goes through handleConnectionWithTLSDetection
	p.handleHTTP(w, r)
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
		sl.conn.Close()
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
