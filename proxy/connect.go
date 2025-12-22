package proxy

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"

	"github.com/coder/boundary/audit"
)

// handleCONNECT handles HTTP CONNECT requests for tunneling
func (p *Server) handleCONNECT(conn net.Conn, req *http.Request) {
	// Extract target from CONNECT request
	// CONNECT requests have the target in req.Host (format: hostname:port)

	p.logger.Debug("🔌 CONNECT request", "target", req.Host)

	// Send 200 Connection established response
	response := "HTTP/1.1 200 Connection established\r\n\r\n"
	_, err := conn.Write([]byte(response))
	if err != nil {
		p.logger.Error("Failed to send CONNECT response", "error", err)
		return
	}

	p.logger.Debug("CONNECT tunnel established", "target", req.Host)

	// Handle the tunnel - decrypt TLS and process each HTTP request
	p.handleCONNECTTunnel(conn)
}

// handleCONNECTTunnel handles the tunnel after CONNECT is established
// It decrypts TLS traffic and processes each HTTP request separately
func (p *Server) handleCONNECTTunnel(conn net.Conn) {
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

		p.logger.Debug("🔒 HTTP Request in CONNECT tunnel", "method", req.Method, "url", req.URL.String(), "target", req.Host)

		// Process this request - check if allowed and forward to target
		p.processTunnelRequest(tlsConn, req)
	}
}

// processTunnelRequest processes a single HTTP request from the CONNECT tunnel
func (p *Server) processTunnelRequest(conn net.Conn, req *http.Request) {
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
	p.forwardRequest(conn, req, true)
}
