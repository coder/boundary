package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/coder/boundary/audit"
)

// handleCONNECT handles HTTP CONNECT requests for tunneling
func (p *Server) handleCONNECT(conn net.Conn, req *http.Request) {
	// Extract target from CONNECT request
	// CONNECT requests have the target in req.Host (format: hostname:port)
	target := req.Host
	if target == "" {
		target = req.URL.Host
	}

	p.logger.Debug("🔌 CONNECT request", "target", target)

	// Check if target is allowed
	// Use "CONNECT" as method and target as the URL for evaluation
	result := p.ruleEngine.Evaluate("CONNECT", target)

	// Audit the CONNECT request
	p.auditor.AuditRequest(audit.Request{
		Method:  "CONNECT",
		URL:     target,
		Host:    target,
		Allowed: result.Allowed,
		Rule:    result.Rule,
	})

	if !result.Allowed {
		p.logger.Debug("CONNECT request blocked", "target", target)
		p.writeBlockedCONNECTResponse(conn, target)
		return
	}

	// Send 200 Connection established response
	response := "HTTP/1.1 200 Connection established\r\n\r\n"
	_, err := conn.Write([]byte(response))
	if err != nil {
		p.logger.Error("Failed to send CONNECT response", "error", err)
		return
	}

	p.logger.Debug("CONNECT tunnel established", "target", target)

	// Handle the tunnel - decrypt TLS and process each HTTP request
	p.handleCONNECTTunnel(conn, target)
}

// handleCONNECTTunnel handles the tunnel after CONNECT is established
// It decrypts TLS traffic and processes each HTTP request separately
func (p *Server) handleCONNECTTunnel(conn net.Conn, target string) {
	defer func() {
		err := conn.Close()
		if err != nil {
			p.logger.Error("Failed to close CONNECT tunnel", "error", err)
		}
	}()

	// Wrap connection with TLS server to decrypt traffic
	tlsConn := tls.Server(conn, p.tlsConfig)

	// Perform TLS handshake
	if err := tlsConn.Handshake(); err != nil {
		p.logger.Error("TLS handshake failed in CONNECT tunnel", "error", err)
		return
	}

	p.logger.Debug("✅ TLS handshake successful in CONNECT tunnel")

	// Process HTTP requests in a loop
	reader := bufio.NewReader(tlsConn)
	for {
		// Read HTTP request from tunnel
		req, err := http.ReadRequest(reader)
		if err != nil {
			if err == io.EOF {
				p.logger.Debug("CONNECT tunnel closed by client")
				break
			}
			p.logger.Error("Failed to read HTTP request from CONNECT tunnel", "error", err)
			break
		}

		p.logger.Debug("🔒 HTTP Request in CONNECT tunnel", "method", req.Method, "url", req.URL.String(), "target", target)

		// Process this request - check if allowed and forward to target
		p.processTunnelRequest(tlsConn, req, target)
	}
}

// processTunnelRequest processes a single HTTP request from the CONNECT tunnel
func (p *Server) processTunnelRequest(conn net.Conn, req *http.Request, targetHost string) {
	// Check if request should be allowed
	// Use the original request URL but evaluate against rules
	urlStr := req.Host + req.URL.String()
	result := p.ruleEngine.Evaluate(req.Method, urlStr)

	// Audit the request
	p.auditor.AuditRequest(audit.Request{
		Method:  req.Method,
		URL:     req.URL.String(),
		Host:    req.Host,
		Allowed: result.Allowed,
		Rule:    result.Rule,
	})

	if !result.Allowed {
		p.logger.Debug("Request in CONNECT tunnel blocked", "method", req.Method, "url", urlStr)
		p.writeBlockedResponse(conn, req)
		return
	}

	// Forward request to target
	// The target is the original CONNECT target, but we use the request's host/path
	p.forwardTunnelRequest(conn, req, targetHost)
}

// forwardTunnelRequest forwards a request from the tunnel to the target
func (p *Server) forwardTunnelRequest(conn net.Conn, req *http.Request, targetHost string) {
	// Create HTTP client
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	// Extract hostname and port from targetHost
	hostname := targetHost
	port := "443" // Default HTTPS port
	if strings.Contains(targetHost, ":") {
		parts := strings.Split(targetHost, ":")
		hostname = parts[0]
		port = parts[1]
	}

	scheme := "https"
	if port == "80" {
		scheme = "http"
	}

	// Build target URL using the request's path but the CONNECT target's host
	// URL.Host can include port for connection, but Host header should not
	targetURL := &url.URL{
		Scheme:   scheme,
		Host:     targetHost, // Include port for connection
		Path:     req.URL.Path,
		RawQuery: req.URL.RawQuery,
	}

	var body = req.Body
	if req.Method == http.MethodGet || req.Method == http.MethodHead {
		body = nil
	}

	newReq, err := http.NewRequest(req.Method, targetURL.String(), body)
	if err != nil {
		p.logger.Error("can't create HTTP request for tunnel", "error", err)
		return
	}

	// Set Host header to just the hostname (without port)
	// The Host header should not include the port number for HTTPS
	newReq.Host = hostname

	// Copy headers (but skip Host since we set it explicitly above)
	for name, values := range req.Header {
		// Skip connection-specific headers and Host header
		lowerName := strings.ToLower(name)
		if lowerName == "connection" || lowerName == "proxy-connection" || lowerName == "host" {
			continue
		}
		for _, value := range values {
			newReq.Header.Add(name, value)
		}
	}

	// Make request to destination
	resp, err := client.Do(newReq)
	if err != nil {
		p.logger.Error("Failed to forward request from CONNECT tunnel", "error", err)
		return
	}

	p.logger.Debug("Response from target", "status", resp.StatusCode, "target", targetHost)

	// Read the body and set Content-Length
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		p.logger.Error("can't read response body from tunnel", "error", err)
		return
	}
	resp.Header.Set("Content-Length", strconv.Itoa(len(bodyBytes)))
	resp.ContentLength = int64(len(bodyBytes))
	err = resp.Body.Close()
	if err != nil {
		p.logger.Error("Failed to close response body", "error", err)
		return
	}
	resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// Normalize to HTTP/1.1
	resp.Proto = "HTTP/1.1"
	resp.ProtoMajor = 1
	resp.ProtoMinor = 1

	// Write response back to tunnel
	err = resp.Write(conn)
	if err != nil {
		p.logger.Error("Failed to write response to CONNECT tunnel", "error", err)
		return
	}

	p.logger.Debug("Successfully forwarded response in CONNECT tunnel")
}

// writeBlockedCONNECTResponse writes a blocked response for CONNECT requests
func (p *Server) writeBlockedCONNECTResponse(conn net.Conn, target string) {
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

	resp.Header.Set("Content-Type", "text/plain")

	body := fmt.Sprintf(`🚫 CONNECT Request Blocked by Boundary

Target: %s

To allow this CONNECT request, restart boundary with:
  --allow "domain=%s"

For more help: https://github.com/coder/boundary
`, target, target)

	resp.Body = io.NopCloser(strings.NewReader(body))
	resp.ContentLength = int64(len(body))

	err := resp.Write(conn)
	if err != nil {
		p.logger.Error("Failed to write blocked CONNECT response", "error", err)
		return
	}
}
