package config

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNewAppConfigFromCliConfig_UpstreamProxy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		raw     string
		port    string
		want    string
		wantErr bool
	}{
		{
			name: "empty by default",
		},
		{
			name: "http upstream proxy",
			raw:  "http://proxy.corp:3128",
			want: "http://proxy.corp:3128",
		},
		{
			name: "https upstream proxy",
			raw:  "https://proxy.corp:8443",
			want: "https://proxy.corp:8443",
		},
		{
			name: "upstream proxy with credentials",
			raw:  "http://user:pass@proxy.corp:3128",
			want: "http://user:pass@proxy.corp:3128",
		},
		{
			name:    "unsupported scheme",
			raw:     "socks5://proxy.corp:1080",
			wantErr: true,
		},
		{
			name:    "missing host",
			raw:     "http:///proxy",
			wantErr: true,
		},
		{
			name:    "invalid port",
			raw:     "http://proxy.corp:badport",
			wantErr: true,
		},
		{
			name:    "out of range port",
			raw:     "http://proxy.corp:70000",
			wantErr: true,
		},
		{
			name: "IPv6 proxy host",
			raw:  "http://[2001:db8::1]:3128",
			want: "http://[2001:db8::1]:3128",
		},
		{
			name:    "localhost boundary proxy loop",
			raw:     "http://localhost:8080",
			wantErr: true,
		},
		{
			name:    "loopback IP boundary proxy loop",
			raw:     "http://127.0.0.1:8080",
			wantErr: true,
		},
		{
			name:    "same custom boundary proxy port loop",
			raw:     "http://localhost:18080",
			port:    "18080",
			wantErr: true,
		},
		{
			name: "local proxy on a different port is allowed",
			raw:  "http://localhost:3128",
			want: "http://localhost:3128",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := baseCliConfig()
			_ = c.ProxyPort.Set("8080")
			if tc.port != "" {
				_ = c.ProxyPort.Set(tc.port)
			}
			if tc.raw != "" {
				_ = c.UpstreamProxy.Set(tc.raw)
			}

			got, err := NewAppConfigFromCliConfig(c, []string{"echo", "hello"}, nil)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.UpstreamProxy != tc.want {
				t.Fatalf("UpstreamProxy: got %q, want %q", got.UpstreamProxy, tc.want)
			}
		})
	}
}

func TestAppConfigJSONOmitsUpstreamProxy(t *testing.T) {
	t.Parallel()

	c := baseCliConfig()
	_ = c.ProxyPort.Set("8080")
	_ = c.UpstreamProxy.Set("http://user:pass@proxy.corp:3128")

	got, err := NewAppConfigFromCliConfig(c, []string{"echo", "hello"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.UpstreamProxy == "" {
		t.Fatal("expected upstream proxy to remain available at runtime")
	}

	payload, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("unexpected marshal error: %v", err)
	}
	configJSON := string(payload)

	for _, forbidden := range []string{"user:pass", "UpstreamProxy", "upstream_proxy"} {
		if strings.Contains(configJSON, forbidden) {
			t.Fatalf("marshaled AppConfig leaked %q in %s", forbidden, configJSON)
		}
	}
}

func TestStripUpstreamProxyArgs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "separate flag value",
			args: []string{"boundary", "--upstream-proxy", "http://user:pass@proxy.corp:3128", "--allow", "domain=example.com", "--", "curl"},
			want: []string{"boundary", "--allow", "domain=example.com", "--", "curl"},
		},
		{
			name: "equals flag value",
			args: []string{"boundary", "--upstream-proxy=http://user:pass@proxy.corp:3128", "--", "curl"},
			want: []string{"boundary", "--", "curl"},
		},
		{
			name: "target args are preserved after separator",
			args: []string{"boundary", "--allow", "domain=example.com", "--", "tool", "--upstream-proxy", "http://target.example"},
			want: []string{"boundary", "--allow", "domain=example.com", "--", "tool", "--upstream-proxy", "http://target.example"},
		},
		{
			name: "args without upstream proxy are copied",
			args: []string{"boundary", "--allow", "domain=example.com", "--", "curl"},
			want: []string{"boundary", "--allow", "domain=example.com", "--", "curl"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := StripUpstreamProxyArgs(tc.args)
			if strings.Join(got, "\x00") != strings.Join(tc.want, "\x00") {
				t.Fatalf("args: got %#v, want %#v", got, tc.want)
			}
			if len(tc.args) > 0 && &got[0] == &tc.args[0] {
				t.Fatal("expected returned args to use a new backing array")
			}
		})
	}
}
