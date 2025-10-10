package proxy

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"strings"
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

func (p *Server) handleConnectionWithTLSDetection(conn net.Conn) {
	defer conn.Close()

	// Detect protocol using TLS handshake detection
	conn, isTLS := p.isTLSConnection(conn)
	if isTLS {
		log.Println("🔒 Detected TLS connection - handling as HTTPS")
		p.handleTLSConnection(conn)
	} else {
		log.Println("🌐 Detected HTTP connection")
		p.handleHTTPConnection(conn)
	}
}

func (p *Server) isTLSConnection(conn net.Conn) (net.Conn, bool) {
	// Read first byte to detect TLS
	buf := make([]byte, 1)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		// TODO: return error?
		return nil, false
	}

	connWrapper := &connectionWrapper{conn, buf, false}

	// TLS detection based on first byte:
	// 0x16 (22) = TLS Handshake
	// 0x17 (23) = TLS Application Data
	// 0x14 (20) = TLS Change Cipher Spec
	// 0x15 (21) = TLS Alert
	isTLS := buf[0] == 0x16 || buf[0] == 0x17 || buf[0] == 0x14 || buf[0] == 0x15

	if isTLS {
		log.Printf("TLS detected: first byte = 0x%02x", buf[0])
	}

	return connWrapper, isTLS
}

func (p *Server) handleHTTPConnection(conn net.Conn) {
	// Read HTTP request
	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		log.Printf("Failed to read HTTP request: %v", err)
		return
	}

	log.Printf("🌐 HTTP Request: %s %s", req.Method, req.URL.String())
	log.Printf("   Host: %s", req.Host)
	log.Printf("   User-Agent: %s", req.Header.Get("User-Agent"))

	// Check if request should be allowed
	result := p.ruleEngine.Evaluate(req.Method, req.Host)

	// Audit the request
	//p.auditor.AuditRequest(audit.Request{
	//	Method:  req.Method,
	//	URL:     req.URL.String(),
	//	Allowed: result.Allowed,
	//	Rule:    result.Rule,
	//})

	if !result.Allowed {
		p.writeBlockedResponse(conn, req)
		return
	}

	// Forward HTTP request to destination
	p.forwardHTTPRequest(conn, req)
}

func (p *Server) handleTLSConnection(conn net.Conn) {
	// Create TLS connection
	tlsConn := tls.Server(conn, p.tlsConfig)

	// Perform TLS handshake
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("TLS handshake failed: %v", err)
		return
	}

	log.Println("✅ TLS handshake successful")

	// Read HTTP request over TLS
	req, err := http.ReadRequest(bufio.NewReader(tlsConn))
	if err != nil {
		log.Printf("Failed to read HTTPS request: %v", err)
		return
	}

	log.Printf("🔒 HTTPS Request: %s %s", req.Method, req.URL.String())
	log.Printf("   Host: %s", req.Host)
	log.Printf("   User-Agent: %s", req.Header.Get("User-Agent"))

	// Forward HTTPS request to destination
	p.forwardHTTPSRequest(tlsConn, req)
}

func (p *Server) forwardHTTPRequest(conn net.Conn, req *http.Request) {
	// Create HTTP client
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	req.RequestURI = ""

	// Set the scheme if it's missing
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}

	// Set the host if it's missing
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}

	// Make request to destination
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to forward HTTP request: %v", err)
		return
	}
	defer resp.Body.Close()

	log.Printf("🌐 HTTP Response: %d %s", resp.StatusCode, resp.Status)

	// Copy response back to client
	resp.Write(conn)
}

func (p *Server) forwardHTTPSRequest(conn net.Conn, req *http.Request) {
	// Create HTTP client
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // For demo purposes
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	req.RequestURI = ""

	// Set the scheme if it's missing
	if req.URL.Scheme == "" {
		req.URL.Scheme = "https"
	}

	// Set the host if it's missing
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}

	// Make request to destination
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to forward HTTPS request: %v", err)
		return
	}
	defer resp.Body.Close()

	log.Printf("🔒 HTTPS Response: %d %s", resp.StatusCode, resp.Status)

	// Copy response back to client
	resp.Write(conn)
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
  --allow "%s"                    # Allow all methods to this host
  --allow "%s %s"          # Allow only %s requests to this host

For more help: https://github.com/coder/boundary
`,
		req.Method, req.URL.Path, host, host, req.Method, host, req.Method)

	resp.Body = io.NopCloser(strings.NewReader(body))
	resp.ContentLength = int64(len(body))

	// Write to connection
	resp.Write(conn)
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
