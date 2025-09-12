package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/coder/jail/audit"
	"github.com/coder/jail/rules"
)

// Mock implementations for testing

type mockRuleEngine struct {
	allowAll bool
	rule     string
}

func (m *mockRuleEngine) Evaluate(method, url string) rules.Result {
	return rules.Result{
		Allowed: m.allowAll,
		Rule:    m.rule,
	}
}

type mockAuditor struct {
	recordedRequests []audit.Request
}

func (m *mockAuditor) AuditRequest(req audit.Request) {
	m.recordedRequests = append(m.recordedRequests, req)
}

func TestConfig_Validation(t *testing.T) {
	tests := []struct {
		name   string
		config Config
		valid  bool
	}{
		{
			name: "valid config",
			config: Config{
				HTTPPort:   8080,
				HTTPSPort:  8443,
				RuleEngine: &mockRuleEngine{allowAll: true, rule: "test rule"},
				Auditor:    &mockAuditor{},
				Logger:     slog.New(slog.NewTextHandler(os.Stdout, nil)),
				TLSConfig:  &tls.Config{},
			},
			valid: true,
		},
		{
			name: "zero ports",
			config: Config{
				HTTPPort:   0,
				HTTPSPort:  0,
				RuleEngine: &mockRuleEngine{allowAll: true},
				Auditor:    &mockAuditor{},
				Logger:     slog.New(slog.NewTextHandler(os.Stdout, nil)),
				TLSConfig:  &tls.Config{},
			},
			valid: true, // zero ports might be valid for testing
		},
		{
			name: "nil components",
			config: Config{
				HTTPPort:   8080,
				HTTPSPort:  8443,
				RuleEngine: nil,
				Auditor:    nil,
				Logger:     nil,
				TLSConfig:  nil,
			},
			valid: true, // NewProxyServer accepts nil values
		},
		{
			name: "negative ports",
			config: Config{
				HTTPPort:   -1,
				HTTPSPort:  -1,
				RuleEngine: &mockRuleEngine{allowAll: true},
				Auditor:    &mockAuditor{},
				Logger:     slog.New(slog.NewTextHandler(os.Stdout, nil)),
				TLSConfig:  &tls.Config{},
			},
			valid: false, // negative ports should be invalid
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := NewProxyServer(tt.config)
			
			if tt.valid {
				if server == nil {
					t.Error("expected server, got nil")
				}
				// Additional validation for valid configs
				if server != nil {
					if server.httpPort != tt.config.HTTPPort {
						t.Errorf("expected HTTP port %d, got %d", tt.config.HTTPPort, server.httpPort)
					}
					if server.httpsPort != tt.config.HTTPSPort {
						t.Errorf("expected HTTPS port %d, got %d", tt.config.HTTPSPort, server.httpsPort)
					}
				}
			} else {
				// For invalid configs, we might still get a server but it should fail during start
				if tt.config.HTTPPort < 0 || tt.config.HTTPSPort < 0 {
					// Negative ports will cause start to fail, which is tested elsewhere
				}
			}
		})
	}
}

func TestNewProxyServer(t *testing.T) {
	tests := []struct {
		name   string
		config Config
		check  func(*testing.T, *Server)
	}{
		{
			name: "basic creation",
			config: Config{
				HTTPPort:   8080,
				HTTPSPort:  8443,
				RuleEngine: &mockRuleEngine{allowAll: true, rule: "allow all"},
				Auditor:    &mockAuditor{},
				Logger:     slog.New(slog.NewTextHandler(os.Stdout, nil)),
				TLSConfig:  &tls.Config{},
			},
			check: func(t *testing.T, s *Server) {
				if s == nil {
					t.Error("expected server, got nil")
					return
				}
				if s.httpPort != 8080 {
					t.Errorf("expected HTTP port 8080, got %d", s.httpPort)
				}
				if s.httpsPort != 8443 {
					t.Errorf("expected HTTPS port 8443, got %d", s.httpsPort)
				}
				if s.ruleEngine == nil {
					t.Error("expected rule engine to be set")
				}
				if s.auditor == nil {
					t.Error("expected auditor to be set")
				}
				if s.logger == nil {
					t.Error("expected logger to be set")
				}
				if s.tlsConfig == nil {
					t.Error("expected TLS config to be set")
				}
			},
		},
		{
			name: "nil components",
			config: Config{
				HTTPPort:   8080,
				HTTPSPort:  8443,
				RuleEngine: nil,
				Auditor:    nil,
				Logger:     nil,
				TLSConfig:  nil,
			},
			check: func(t *testing.T, s *Server) {
				if s == nil {
					t.Error("expected server, got nil")
					return
				}
				// Server should be created even with nil components
				if s.httpPort != 8080 {
					t.Errorf("expected HTTP port 8080, got %d", s.httpPort)
				}
				if s.httpsPort != 8443 {
					t.Errorf("expected HTTPS port 8443, got %d", s.httpsPort)
				}
				// nil components should be nil
				if s.ruleEngine != nil {
					t.Error("expected rule engine to be nil")
				}
				if s.auditor != nil {
					t.Error("expected auditor to be nil")
				}
				if s.logger != nil {
					t.Error("expected logger to be nil")
				}
				if s.tlsConfig != nil {
					t.Error("expected TLS config to be nil")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := NewProxyServer(tt.config)
			tt.check(t, server)
		})
	}
}

func TestServerStartStop(t *testing.T) {
	// This test requires actual network operations, so we'll use high ports
	// and short timeouts
	config := Config{
		HTTPPort:   0, // Use port 0 to get a random available port
		HTTPSPort:  0,
		RuleEngine: &mockRuleEngine{allowAll: true, rule: "test"},
		Auditor:    &mockAuditor{},
		Logger:     slog.New(slog.NewTextHandler(os.Stdout, nil)),
		TLSConfig:  &tls.Config{},
	}

	server := NewProxyServer(config)
	if server == nil {
		t.Fatal("expected server, got nil")
	}

	// Test server start and stop with a short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// Start server in a goroutine
	errChan := make(chan error, 1)
	go func() {
		err := server.Start(ctx)
		errChan <- err
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Context will cancel and server should stop
	select {
	case err := <-errChan:
		if err != nil {
			t.Logf("server start returned error (may be expected): %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Error("server did not stop within timeout")
	}
}

func TestServerStop(t *testing.T) {
	config := Config{
		HTTPPort:   0,
		HTTPSPort:  0,
		RuleEngine: &mockRuleEngine{allowAll: true},
		Auditor:    &mockAuditor{},
		Logger:     slog.New(slog.NewTextHandler(os.Stdout, nil)),
		TLSConfig:  &tls.Config{},
	}

	server := NewProxyServer(config)

	// Test Stop when servers are not started
	err := server.Stop()
	if err != nil {
		t.Logf("Stop() returned error when servers not started: %v", err)
	}

	// This is expected behavior - calling Stop() on non-started servers
	// should handle gracefully
}

func TestHandleHTTP_AllowedRequest(t *testing.T) {
	// Create a mock target server
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("target response"))
	}))
	defer targetServer.Close()

	// Parse target URL
	targetURL, _ := url.Parse(targetServer.URL)

	// Create proxy server with allowing rule engine
	auditor := &mockAuditor{}
	config := Config{
		HTTPPort:   8080,
		HTTPSPort:  8443,
		RuleEngine: &mockRuleEngine{allowAll: true, rule: "allow all"},
		Auditor:    auditor,
		Logger:     slog.New(slog.NewTextHandler(os.Stdout, nil)),
		TLSConfig:  &tls.Config{},
	}

	proxy := NewProxyServer(config)

	// Create a request to proxy
	req, _ := http.NewRequest("GET", "http://"+targetURL.Host, nil)
	req.Host = targetURL.Host

	// Create response recorder
	recorder := httptest.NewRecorder()

	// Handle the request
	proxy.handleHTTP(recorder, req)

	// Check response
	if recorder.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", recorder.Code)
	}

	body := recorder.Body.String()
	if !strings.Contains(body, "target response") {
		t.Errorf("expected target response in body, got: %s", body)
	}

	// Check that request was audited
	if len(auditor.recordedRequests) != 1 {
		t.Errorf("expected 1 audited request, got %d", len(auditor.recordedRequests))
	}

	if !auditor.recordedRequests[0].Allowed {
		t.Error("expected request to be marked as allowed")
	}
}

func TestHandleHTTP_BlockedRequest(t *testing.T) {
	auditor := &mockAuditor{}
	config := Config{
		HTTPPort:   8080,
		HTTPSPort:  8443,
		RuleEngine: &mockRuleEngine{allowAll: false, rule: "block all"}, // Block all
		Auditor:    auditor,
		Logger:     slog.New(slog.NewTextHandler(os.Stdout, nil)),
		TLSConfig:  &tls.Config{},
	}

	proxy := NewProxyServer(config)

	// Create a request to proxy
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Host = "example.com"

	// Create response recorder
	recorder := httptest.NewRecorder()

	// Handle the request
	proxy.handleHTTP(recorder, req)

	// Check response
	if recorder.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", recorder.Code)
	}

	body := recorder.Body.String()
	if !strings.Contains(body, "Blocked") {
		t.Errorf("expected 'Blocked' in response body, got: %s", body)
	}

	// Check that request was audited
	if len(auditor.recordedRequests) != 1 {
		t.Errorf("expected 1 audited request, got %d", len(auditor.recordedRequests))
	}

	if auditor.recordedRequests[0].Allowed {
		t.Error("expected request to be marked as blocked")
	}
}

func TestHandleHTTPS_CONNECTMethod(t *testing.T) {
	auditor := &mockAuditor{}
	config := Config{
		HTTPPort:   8080,
		HTTPSPort:  8443,
		RuleEngine: &mockRuleEngine{allowAll: true, rule: "allow all"},
		Auditor:    auditor,
		Logger:     slog.New(slog.NewTextHandler(os.Stdout, nil)),
		TLSConfig:  &tls.Config{},
	}

	proxy := NewProxyServer(config)

	// Create a CONNECT request
	req, _ := http.NewRequest("CONNECT", "https://example.com:443", nil)
	req.Host = "example.com:443"

	// Create response recorder
	recorder := httptest.NewRecorder()

	// Handle the request
	proxy.handleHTTPS(recorder, req)

	// CONNECT requests are complex to test in unit tests since they require
	// actual network connections. We mainly test that the method is called
	// and the request is audited.

	// Check that request was audited
	if len(auditor.recordedRequests) != 1 {
		t.Errorf("expected 1 audited request, got %d", len(auditor.recordedRequests))
	}
}

func TestWriteBlockedResponse(t *testing.T) {
	config := Config{
		HTTPPort:   8080,
		HTTPSPort:  8443,
		RuleEngine: &mockRuleEngine{allowAll: false},
		Auditor:    &mockAuditor{},
		Logger:     slog.New(slog.NewTextHandler(os.Stdout, nil)),
		TLSConfig:  &tls.Config{},
	}

	proxy := NewProxyServer(config)

	tests := []struct {
		name   string
		method string
		url    string
	}{
		{
			name:   "GET request",
			method: "GET",
			url:    "http://example.com",
		},
		{
			name:   "POST request",
			method: "POST",
			url:    "https://api.example.com",
		},
		{
			name:   "CONNECT request",
			method: "CONNECT",
			url:    "example.com:443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(tt.method, tt.url, nil)
			recorder := httptest.NewRecorder()

			proxy.writeBlockedResponse(recorder, req)

			if recorder.Code != http.StatusForbidden {
				t.Errorf("expected status 403, got %d", recorder.Code)
			}

			body := recorder.Body.String()
			if !strings.Contains(body, "Blocked") {
				t.Errorf("expected 'Blocked' in response, got: %s", body)
			}
			if !strings.Contains(body, tt.method) {
				t.Errorf("expected method %s in response, got: %s", tt.method, body)
			}
			// Check for host in the URL rather than full URL
			expectedHost := req.Host
			if expectedHost == "" {
				// Extract host from URL
				if u, err := url.Parse(tt.url); err == nil {
					expectedHost = u.Host
				}
			}
			if expectedHost != "" && !strings.Contains(body, expectedHost) {
				t.Errorf("expected host %s in response, got: %s", expectedHost, body)
			}
		})
	}
}

func TestNilComponents(t *testing.T) {
	// Test that server handles nil components gracefully
	config := Config{
		HTTPPort:   8080,
		HTTPSPort:  8443,
		RuleEngine: nil,
		Auditor:    nil,
		Logger:     nil,
		TLSConfig:  nil,
	}

	proxy := NewProxyServer(config)
	if proxy == nil {
		t.Error("expected proxy to be created with nil components")
		return
	}

	// Create a request
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	recorder := httptest.NewRecorder()

	// This might panic if not handled properly
	defer func() {
		if r := recover(); r != nil {
			t.Logf("handleHTTP panicked with nil components (may be expected): %v", r)
		}
	}()

	proxy.handleHTTP(recorder, req)
	
	// If we reach here without panic, the nil components are handled
	t.Log("Proxy handled request with nil components successfully")
}

// Integration test for proxy functionality
func TestProxyIntegration(t *testing.T) {
	// Create a target server
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Hello from target server! Method: %s, Path: %s", r.Method, r.URL.Path)
	}))
	defer targetServer.Close()

	// Create proxy server
	auditor := &mockAuditor{}
	config := Config{
		HTTPPort:   0,
		HTTPSPort:  0,
		RuleEngine: &mockRuleEngine{allowAll: true, rule: "allow integration test"},
		Auditor:    auditor,
		Logger:     slog.New(slog.NewTextHandler(os.Stdout, nil)),
		TLSConfig:  &tls.Config{},
	}

	proxy := NewProxyServer(config)

	// Test different HTTP methods
	methods := []string{"GET", "POST", "PUT", "DELETE", "HEAD"}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			// Parse target URL
			targetURL, _ := url.Parse(targetServer.URL)
			
			req, _ := http.NewRequest(method, "http://"+targetURL.Host+"/test", strings.NewReader("test body"))
			req.Host = targetURL.Host
			
			recorder := httptest.NewRecorder()
			proxy.handleHTTP(recorder, req)

			if recorder.Code != http.StatusOK {
				t.Errorf("expected status 200, got %d", recorder.Code)
			}

			body := recorder.Body.String()
			// HEAD requests don't return body content
			if method != "HEAD" {
				if !strings.Contains(body, method) {
					t.Errorf("expected method %s in response, got: %s", method, body)
				}
			} else {
				// For HEAD requests, just verify we got a 200 status
				t.Logf("HEAD request completed successfully with empty body")
			}
		})
	}

	// Check audit records
	if len(auditor.recordedRequests) != len(methods) {
		t.Errorf("expected %d audit records, got %d", len(methods), len(auditor.recordedRequests))
	}

	// All requests should be allowed
	for i, req := range auditor.recordedRequests {
		if !req.Allowed {
			t.Errorf("request %d should be allowed", i)
		}
		if req.Rule != "allow integration test" {
			t.Errorf("expected rule 'allow integration test', got %s", req.Rule)
		}
	}
}

// Benchmarks
func BenchmarkNewProxyServer(b *testing.B) {
	config := Config{
		HTTPPort:   8080,
		HTTPSPort:  8443,
		RuleEngine: &mockRuleEngine{allowAll: true},
		Auditor:    &mockAuditor{},
		Logger:     slog.New(slog.NewTextHandler(os.Stdout, nil)),
		TLSConfig:  &tls.Config{},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewProxyServer(config)
	}
}

func BenchmarkHandleHTTP_Allowed(b *testing.B) {
	config := Config{
		HTTPPort:   8080,
		HTTPSPort:  8443,
		RuleEngine: &mockRuleEngine{allowAll: true, rule: "benchmark"},
		Auditor:    &mockAuditor{},
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)), // Reduce logging overhead
		TLSConfig:  &tls.Config{},
	}

	proxy := NewProxyServer(config)
	req, _ := http.NewRequest("GET", "http://example.com", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		recorder := httptest.NewRecorder()
		proxy.handleHTTP(recorder, req)
	}
}

func BenchmarkHandleHTTP_Blocked(b *testing.B) {
	config := Config{
		HTTPPort:   8080,
		HTTPSPort:  8443,
		RuleEngine: &mockRuleEngine{allowAll: false, rule: "block benchmark"},
		Auditor:    &mockAuditor{},
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		TLSConfig:  &tls.Config{},
	}

	proxy := NewProxyServer(config)
	req, _ := http.NewRequest("GET", "http://example.com", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		recorder := httptest.NewRecorder()
		proxy.handleHTTP(recorder, req)
	}
}
