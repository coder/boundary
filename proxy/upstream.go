package proxy

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// NewForwardTransport builds the outbound transport Boundary uses after a
// request has passed policy evaluation. When upstreamProxy is empty, callers
// should leave Config.ForwardTransport nil to preserve the default transport.
func NewForwardTransport(upstreamProxy string) (http.RoundTripper, error) {
	upstreamProxy = strings.TrimSpace(upstreamProxy)
	if upstreamProxy == "" {
		return nil, nil
	}

	upstreamURL, err := url.Parse(upstreamProxy)
	if err != nil {
		return nil, fmt.Errorf("parse upstream proxy URL: %w", err)
	}

	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("default HTTP transport is %T, want *http.Transport", http.DefaultTransport)
	}

	transport := defaultTransport.Clone()
	transport.Proxy = http.ProxyURL(upstreamURL)
	return transport, nil
}

// RedactProxyURL removes userinfo from a proxy URL before it is logged.
func RedactProxyURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.User = nil
	return u.String()
}
