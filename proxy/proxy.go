package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"boundary/rules"
)

// ProxyServer handles HTTP and HTTPS requests with rule-based filtering
type ProxyServer struct {
	httpServer  *http.Server
	httpsServer *http.Server
	ruleEngine  *rules.RuleEngine
	logger      *slog.Logger
	tlsConfig   *tls.Config
	httpPort    int
	httpsPort   int
}

// Config holds configuration for the proxy server
type Config struct {
	HTTPPort   int
	HTTPSPort  int
	RuleEngine *rules.RuleEngine
	Logger     *slog.Logger
	TLSConfig  *tls.Config
}

// NewProxyServer creates a new proxy server instance
func NewProxyServer(config Config) *ProxyServer {
	return &ProxyServer{
		ruleEngine: config.RuleEngine,
		logger:     config.Logger,
		tlsConfig:  config.TLSConfig,
		httpPort:   config.HTTPPort,
		httpsPort:  config.HTTPSPort,
	}
}

// Start starts both HTTP and HTTPS proxy servers
func (p *ProxyServer) Start(ctx context.Context) error {
	// Create HTTP server
	p.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", p.httpPort),
		Handler: http.HandlerFunc(p.handleHTTP),
	}

	// Create HTTPS server
	p.httpsServer = &http.Server{
		Addr:      fmt.Sprintf(":%d", p.httpsPort),
		Handler:   http.HandlerFunc(p.handleHTTPS),
		TLSConfig: p.tlsConfig,
	}

	// Start HTTP server
	go func() {
		p.logger.Info("Starting HTTP proxy", "port", p.httpPort)
		if err := p.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			p.logger.Error("HTTP proxy server error", "error", err)
		}
	}()

	// Start HTTPS server
	go func() {
		p.logger.Info("Starting HTTPS proxy", "port", p.httpsPort)
		if err := p.httpsServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			p.logger.Error("HTTPS proxy server error", "error", err)
		}
	}()

	// Wait for context cancellation
	<-ctx.Done()
	return p.Stop()
}

// Stop stops both proxy servers
func (p *ProxyServer) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var httpErr, httpsErr error
	if p.httpServer != nil {
		httpErr = p.httpServer.Shutdown(ctx)
	}
	if p.httpsServer != nil {
		httpsErr = p.httpsServer.Shutdown(ctx)
	}

	if httpErr != nil {
		return httpErr
	}
	return httpsErr
}

// handleHTTP handles regular HTTP requests
func (p *ProxyServer) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Check if request should be allowed
	action := p.ruleEngine.Evaluate(r.Method, r.URL.String())
	if action == rules.Deny {
		p.writeBlockedResponse(w, r)
		return
	}

	// Handle CONNECT method for HTTPS tunneling
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}

	// Forward regular HTTP request
	p.forwardHTTPRequest(w, r)
}

// handleHTTPS handles HTTPS requests (after TLS termination)
func (p *ProxyServer) handleHTTPS(w http.ResponseWriter, r *http.Request) {
	// Reconstruct the full URL for HTTPS requests
	fullURL := fmt.Sprintf("https://%s%s", r.Host, r.URL.Path)
	if r.URL.RawQuery != "" {
		fullURL += "?" + r.URL.RawQuery
	}

	// Check if request should be allowed
	action := p.ruleEngine.Evaluate(r.Method, fullURL)
	if action == rules.Deny {
		p.writeBlockedResponse(w, r)
		return
	}

	// Forward HTTPS request
	p.forwardHTTPSRequest(w, r)
}

// handleConnect handles CONNECT requests for HTTPS tunneling
func (p *ProxyServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	// Extract host and port
	host := r.URL.Host
	if !strings.Contains(host, ":") {
		host += ":443" // Default HTTPS port
	}

	// Check if CONNECT should be allowed
	connectURL := fmt.Sprintf("https://%s", strings.Split(host, ":")[0])
	action := p.ruleEngine.Evaluate("CONNECT", connectURL)
	if action == rules.Deny {
		p.writeBlockedResponse(w, r)
		return
	}

	// Establish connection to target server
	targetConn, err := net.DialTimeout("tcp", host, 10*time.Second)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to connect to %s: %v", host, err), http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	// Send 200 Connection Established
	w.WriteHeader(http.StatusOK)

	// Get the underlying connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to hijack connection: %v", err), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Relay data between client and target
	p.relayConnections(clientConn, targetConn)
}

// forwardHTTPRequest forwards a regular HTTP request
func (p *ProxyServer) forwardHTTPRequest(w http.ResponseWriter, r *http.Request) {
	// Create a new request to the target server
	targetURL := r.URL
	if targetURL.Scheme == "" {
		targetURL.Scheme = "http"
	}
	if targetURL.Host == "" {
		targetURL.Host = r.Host
	}

	// Create HTTP client
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	// Create new request
	req, err := http.NewRequest(r.Method, targetURL.String(), r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create request: %v", err), http.StatusInternalServerError)
		return
	}

	// Copy headers
	for name, values := range r.Header {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}

	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to make request: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for name, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}

	// Copy status code
	w.WriteHeader(resp.StatusCode)

	// Copy response body
	io.Copy(w, resp.Body)
}

// forwardHTTPSRequest forwards an HTTPS request
func (p *ProxyServer) forwardHTTPSRequest(w http.ResponseWriter, r *http.Request) {
	// Create target URL
	targetURL := &url.URL{
		Scheme:   "https",
		Host:     r.Host,
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}

	// Create HTTPS client
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Create new request
	req, err := http.NewRequest(r.Method, targetURL.String(), r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create request: %v", err), http.StatusInternalServerError)
		return
	}

	// Copy headers
	for name, values := range r.Header {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}

	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to make request: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for name, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}

	// Copy status code
	w.WriteHeader(resp.StatusCode)

	// Copy response body
	io.Copy(w, resp.Body)
}

// writeBlockedResponse writes a blocked response
func (p *ProxyServer) writeBlockedResponse(w http.ResponseWriter, r *http.Request) {
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
Reason: No matching allow rules (default deny-all policy)

To allow this request, restart boundary with:
  --allow "%s"                    # Allow all methods to this host
  --allow "%s %s"          # Allow only %s requests to this host

For more help: https://github.com/coder/boundary
`, 
		r.Method, r.URL.Path, host, host, r.Method, host, r.Method)
}

// relayConnections relays data between two connections
func (p *ProxyServer) relayConnections(client, target net.Conn) {
	done := make(chan struct{}, 2)

	// Client to target
	go func() {
		defer func() { done <- struct{}{} }()
		io.Copy(target, client)
	}()

	// Target to client
	go func() {
		defer func() { done <- struct{}{} }()
		io.Copy(client, target)
	}()

	// Wait for one direction to finish
	<-done
}