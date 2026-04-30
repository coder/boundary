package config

import (
	"testing"
)

func TestParseInjectTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    InjectTarget
		wantErr bool
	}{
		{
			name:  "domain only",
			input: "domain=dev.coder.com",
			want:  InjectTarget{Domain: "dev.coder.com"},
		},
		{
			name:  "domain and path",
			input: "domain=dev.coder.com path=/api/v2/aibridge/*",
			want:  InjectTarget{Domain: "dev.coder.com", Path: "/api/v2/aibridge/*"},
		},
		{
			name:  "leading and trailing whitespace",
			input: "  domain=dev.coder.com path=/api/* ",
			want:  InjectTarget{Domain: "dev.coder.com", Path: "/api/*"},
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "whitespace only",
			input:   "   ",
			wantErr: true,
		},
		{
			name:    "missing domain",
			input:   "path=/api/*",
			wantErr: true,
		},
		{
			name:    "empty domain value",
			input:   "domain=",
			wantErr: true,
		},
		{
			name:    "malformed pair no equals",
			input:   "domain",
			wantErr: true,
		},
		{
			name:    "unknown key",
			input:   "domain=example.com port=443",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParseInjectTarget(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Domain != tc.want.Domain {
				t.Errorf("Domain: got %q, want %q", got.Domain, tc.want.Domain)
			}
			if got.Path != tc.want.Path {
				t.Errorf("Path: got %q, want %q", got.Path, tc.want.Path)
			}
		})
	}
}

func TestValidateSessionCorrelation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     SessionCorrelationConfig
		wantErr bool
	}{
		{
			name: "disabled is always valid",
			cfg: SessionCorrelationConfig{
				Enabled: false,
			},
		},
		{
			name: "disabled with empty targets is valid",
			cfg: SessionCorrelationConfig{
				Enabled:       false,
				InjectTargets: nil,
			},
		},
		{
			name: "enabled with targets and default headers",
			cfg: SessionCorrelationConfig{
				Enabled:                  true,
				InjectTargets:            []InjectTarget{{Domain: "dev.coder.com"}},
				SessionIDHeaderName:      DefaultSessionIDHeaderName,
				SequenceNumberHeaderName: DefaultSequenceNumberHeaderName,
			},
		},
		{
			name: "enabled with custom headers",
			cfg: SessionCorrelationConfig{
				Enabled:                  true,
				InjectTargets:            []InjectTarget{{Domain: "example.com", Path: "/api/*"}},
				SessionIDHeaderName:      "X-Custom-Session",
				SequenceNumberHeaderName: "X-Custom-Seq",
			},
		},
		{
			name: "enabled with no targets",
			cfg: SessionCorrelationConfig{
				Enabled:                  true,
				InjectTargets:            nil,
				SessionIDHeaderName:      DefaultSessionIDHeaderName,
				SequenceNumberHeaderName: DefaultSequenceNumberHeaderName,
			},
			wantErr: true,
		},
		{
			name: "enabled with empty targets slice",
			cfg: SessionCorrelationConfig{
				Enabled:                  true,
				InjectTargets:            []InjectTarget{},
				SessionIDHeaderName:      DefaultSessionIDHeaderName,
				SequenceNumberHeaderName: DefaultSequenceNumberHeaderName,
			},
			wantErr: true,
		},
		{
			name: "enabled with empty session id header",
			cfg: SessionCorrelationConfig{
				Enabled:                  true,
				InjectTargets:            []InjectTarget{{Domain: "example.com"}},
				SessionIDHeaderName:      "",
				SequenceNumberHeaderName: DefaultSequenceNumberHeaderName,
			},
			wantErr: true,
		},
		{
			name: "enabled with empty sequence number header",
			cfg: SessionCorrelationConfig{
				Enabled:                  true,
				InjectTargets:            []InjectTarget{{Domain: "example.com"}},
				SessionIDHeaderName:      DefaultSessionIDHeaderName,
				SequenceNumberHeaderName: "",
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateSessionCorrelation(tc.cfg)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestNewAppConfigFromCliConfig_SessionCorrelation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cli     CliConfig
		want    SessionCorrelationConfig
		wantErr bool
	}{
		{
			name: "defaults when not configured",
			cli:  baseCliConfig(),
			want: SessionCorrelationConfig{
				Enabled:                  false,
				InjectTargets:            nil,
				SessionIDHeaderName:      DefaultSessionIDHeaderName,
				SequenceNumberHeaderName: DefaultSequenceNumberHeaderName,
			},
		},
		{
			name: "enabled with inject targets",
			cli: func() CliConfig {
				c := baseCliConfig()
				c.SessionCorrelationEnabled.Set("true")
				_ = c.InjectSessionIDOn.Set("domain=dev.coder.com path=/api/v2/aibridge/*")
				return c
			}(),
			want: SessionCorrelationConfig{
				Enabled: true,
				InjectTargets: []InjectTarget{
					{Domain: "dev.coder.com", Path: "/api/v2/aibridge/*"},
				},
				SessionIDHeaderName:      DefaultSessionIDHeaderName,
				SequenceNumberHeaderName: DefaultSequenceNumberHeaderName,
			},
		},
		{
			name: "custom header names",
			cli: func() CliConfig {
				c := baseCliConfig()
				c.SessionCorrelationEnabled.Set("true")
				_ = c.InjectSessionIDOn.Set("domain=example.com")
				c.SessionIDHeaderName.Set("X-My-Session")
				c.SequenceNumberHeaderName.Set("X-My-Seq")
				return c
			}(),
			want: SessionCorrelationConfig{
				Enabled:                  true,
				InjectTargets:            []InjectTarget{{Domain: "example.com"}},
				SessionIDHeaderName:      "X-My-Session",
				SequenceNumberHeaderName: "X-My-Seq",
			},
		},
		{
			name: "enabled with no targets fails validation",
			cli: func() CliConfig {
				c := baseCliConfig()
				c.SessionCorrelationEnabled.Set("true")
				return c
			}(),
			wantErr: true,
		},
		{
			name: "invalid inject target",
			cli: func() CliConfig {
				c := baseCliConfig()
				c.SessionCorrelationEnabled.Set("true")
				_ = c.InjectSessionIDOn.Set("notakey")
				return c
			}(),
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := NewAppConfigFromCliConfig(tc.cli, []string{"echo", "hello"})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			sc := got.SessionCorrelation
			if sc.Enabled != tc.want.Enabled {
				t.Errorf("Enabled: got %v, want %v", sc.Enabled, tc.want.Enabled)
			}
			if sc.SessionIDHeaderName != tc.want.SessionIDHeaderName {
				t.Errorf("SessionIDHeaderName: got %q, want %q",
					sc.SessionIDHeaderName, tc.want.SessionIDHeaderName)
			}
			if sc.SequenceNumberHeaderName != tc.want.SequenceNumberHeaderName {
				t.Errorf("SequenceNumberHeaderName: got %q, want %q",
					sc.SequenceNumberHeaderName, tc.want.SequenceNumberHeaderName)
			}
			if len(sc.InjectTargets) != len(tc.want.InjectTargets) {
				t.Fatalf("InjectTargets len: got %d, want %d",
					len(sc.InjectTargets), len(tc.want.InjectTargets))
			}
			for i := range sc.InjectTargets {
				if sc.InjectTargets[i].Domain != tc.want.InjectTargets[i].Domain {
					t.Errorf("InjectTargets[%d].Domain: got %q, want %q",
						i, sc.InjectTargets[i].Domain, tc.want.InjectTargets[i].Domain)
				}
				if sc.InjectTargets[i].Path != tc.want.InjectTargets[i].Path {
					t.Errorf("InjectTargets[%d].Path: got %q, want %q",
						i, sc.InjectTargets[i].Path, tc.want.InjectTargets[i].Path)
				}
			}
		})
	}
}

// baseCliConfig returns a CliConfig with valid defaults for fields that
// NewAppConfigFromCliConfig requires, so tests can focus on the session
// correlation fields without tripping over unrelated validation.
func baseCliConfig() CliConfig {
	c := CliConfig{}
	c.JailType.Set("nsjail")
	c.SessionIDHeaderName.Set(DefaultSessionIDHeaderName)
	c.SequenceNumberHeaderName.Set(DefaultSequenceNumberHeaderName)
	return c
}
