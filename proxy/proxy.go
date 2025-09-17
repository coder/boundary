package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/coder/jail/audit"
	"github.com/coder/jail/rules"
)

// Server handles HTTP and HTTPS requests with rule-based filtering
type Server struct {
	ruleEngine rules.Engine
	auditor    audit.Auditor
	logger     *slog.Logger
	tlsConfig  *tls.Config
	httpPort   int
	httpsPort  int

	httpServer  *http.Server
	httpsServer *http.Server
}

// Config holds configuration for the proxy server
type Config struct {
	HTTPPort   int
	HTTPSPort  int
	RuleEngine rules.Engine
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
		httpsPort:  config.HTTPSPort,
	}
}

// Start starts both HTTP and HTTPS proxy servers
func (p *Server) Start(ctx context.Context) error {
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
		err := p.httpServer.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			p.logger.Error("HTTP proxy server error", "error", err)
		}
	}()

	// Start HTTPS server
	go func() {
		p.logger.Info("Starting HTTPS proxy", "port", p.httpsPort)
		err := p.httpsServer.ListenAndServeTLS("", "")
		if err != nil && err != http.ErrServerClosed {
			p.logger.Error("HTTPS proxy server error", "error", err)
		}
	}()

	// Wait for context cancellation
	<-ctx.Done()
	return p.Stop()
}

// Stop stops both proxy servers
func (p *Server) Stop() error {
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
func (p *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Check if request should be allowed
	result, err := p.ruleEngine.Evaluate(r)
	if err != nil {
		p.logger.Error("could not validate request because it failed to parse", "error", err)
	}

	// Audit the request
	p.auditor.AuditRequest(audit.Request{
		Method:  r.Method,
		URL:     r.URL.String(),
		Allowed: result.Allowed,
		Rule:    result.Rule.String(),
	})

	if !result.Allowed {
		p.writeBlockedResponse(w, r)
		return
	}

	// Forward regular HTTP request
	p.forwardHTTPRequest(w, r)
}

// handleHTTPS handles HTTPS requests (after TLS termination)
func (p *Server) handleHTTPS(w http.ResponseWriter, r *http.Request) {
	// Check if request should be allowed
	result, err := p.ruleEngine.Evaluate(r)
	if err != nil {
		p.logger.Error("could not parse request", "error", err)
	}

	// Audit the request
	p.auditor.AuditRequest(audit.Request{
		Method:  r.Method,
		URL:     r.URL.String(),
		Allowed: result.Allowed,
		Rule:    result.Rule.String(),
	})

	if !result.Allowed {
		p.writeBlockedResponse(w, r)
		return
	}

	// Forward HTTPS request
	p.forwardHTTPSRequest(w, r)
}

// forwardHTTPRequest forwards a regular HTTP request
func (p *Server) forwardHTTPRequest(w http.ResponseWriter, r *http.Request) {
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
func (p *Server) forwardHTTPSRequest(w http.ResponseWriter, r *http.Request) {
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
func (p *Server) writeBlockedResponse(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusForbidden)

	// Extract host from URL for cleaner display
	host := r.URL.Host
	if host == "" {
		host = r.Host
	}

	fmt.Fprintf(w, `🚫 Request Blocked by Coder Jail

Request: %s %s
Host: %s

To allow this request, restart jail with:
  --allow "%s"                    # Allow all methods to this host
  --allow "%s %s"          # Allow only %s requests to this host

For more help: https://github.com/coder/jail
`,
		r.Method, r.URL.Path, host, host, r.Method, host, r.Method)
}
