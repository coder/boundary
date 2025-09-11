package audit

import "net/http"

// Request represents information about an HTTP request for auditing
type Request struct {
	Method  string
	URL     string
	Allowed bool
	Rule    string // The rule that matched (if any)
}

// HTTPRequestToAuditRequest converts an http.Request to an audit.Request
func HTTPRequestToAuditRequest(httpReq *http.Request) *Request {
	return &Request{
		Method: httpReq.Method,
		URL:    httpReq.URL.String(),
	}
}
