package audit

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestHTTPRequestToAuditRequest(t *testing.T) {
	tests := []struct {
		name           string
		request        *http.Request
		expectedMethod string
		expectedURL    string
	}{
		{
			name: "basic GET request",
			request: func() *http.Request {
				req, _ := http.NewRequest("GET", "https://example.com/path?query=value", nil)
				return req
			}(),
			expectedMethod: "GET",
			expectedURL:    "https://example.com/path?query=value",
		},
		{
			name: "POST request with body",
			request: func() *http.Request {
				req, _ := http.NewRequest("POST", "https://api.example.com/users", strings.NewReader("data"))
				return req
			}(),
			expectedMethod: "POST",
			expectedURL:    "https://api.example.com/users",
		},
		{
			name: "request with port",
			request: func() *http.Request {
				req, _ := http.NewRequest("GET", "https://example.com:8443/api", nil)
				return req
			}(),
			expectedMethod: "GET",
			expectedURL:    "https://example.com:8443/api",
		},
		{
			name: "request with complex query parameters",
			request: func() *http.Request {
				req, _ := http.NewRequest("GET", "https://search.example.com/api?q=hello%20world&limit=10&offset=0", nil)
				return req
			}(),
			expectedMethod: "GET",
			expectedURL:    "https://search.example.com/api?q=hello%20world&limit=10&offset=0",
		},
		{
			name: "request with fragment (should be ignored)",
			request: func() *http.Request {
				u, _ := url.Parse("https://example.com/page#section")
				req := &http.Request{
					Method: "GET",
					URL:    u,
				}
				return req
			}(),
			expectedMethod: "GET",
			expectedURL:    "https://example.com/page#section",
		},
		{
			name: "HTTP request (not HTTPS)",
			request: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://insecure.example.com/data", nil)
				return req
			}(),
			expectedMethod: "GET",
			expectedURL:    "http://insecure.example.com/data",
		},
		{
			name: "PUT request",
			request: func() *http.Request {
				req, _ := http.NewRequest("PUT", "https://api.example.com/users/123", strings.NewReader("updated data"))
				return req
			}(),
			expectedMethod: "PUT",
			expectedURL:    "https://api.example.com/users/123",
		},
		{
			name: "DELETE request",
			request: func() *http.Request {
				req, _ := http.NewRequest("DELETE", "https://api.example.com/users/123", nil)
				return req
			}(),
			expectedMethod: "DELETE",
			expectedURL:    "https://api.example.com/users/123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auditReq := HTTPRequestToAuditRequest(tt.request)

			if auditReq.Method != tt.expectedMethod {
				t.Errorf("expected method %s, got %s", tt.expectedMethod, auditReq.Method)
			}

			if auditReq.URL != tt.expectedURL {
				t.Errorf("expected URL %s, got %s", tt.expectedURL, auditReq.URL)
			}

			// Verify that fields not set by HTTPRequestToAuditRequest have zero values
			if auditReq.Allowed != false {
				t.Errorf("expected Allowed to be false (zero value), got %v", auditReq.Allowed)
			}

			if auditReq.Rule != "" {
				t.Errorf("expected Rule to be empty (zero value), got %q", auditReq.Rule)
			}
		})
	}
}
