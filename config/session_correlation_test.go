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
		environ []string
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
				_ = c.SessionCorrelationEnabled.Set("true")
				_ = c.InjectSessionIDTarget.Set("domain=dev.coder.com path=/api/v2/aibridge/*")
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
				_ = c.SessionCorrelationEnabled.Set("true")
				_ = c.InjectSessionIDTarget.Set("domain=example.com")
				_ = c.SessionIDHeaderName.Set("X-My-Session")
				_ = c.SequenceNumberHeaderName.Set("X-My-Seq")
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
			name: "enabled with no targets, CODER_AGENT_URL set → auto-derived",
			cli: func() CliConfig {
				c := baseCliConfig()
				_ = c.SessionCorrelationEnabled.Set("true")
				return c
			}(),
			environ: []string{"CODER_AGENT_URL=https://dev.coder.com/"},
			want: SessionCorrelationConfig{
				Enabled:                  true,
				InjectTargets:            []InjectTarget{{Domain: "dev.coder.com", Path: DefaultAIBridgePath}},
				SessionIDHeaderName:      DefaultSessionIDHeaderName,
				SequenceNumberHeaderName: DefaultSequenceNumberHeaderName,
			},
		},
		{
			name: "enabled with no targets, CODER_AGENT_URL absent → error",
			cli: func() CliConfig {
				c := baseCliConfig()
				_ = c.SessionCorrelationEnabled.Set("true")
				return c
			}(),
			environ: []string{},
			wantErr: true,
		},
		{
			name: "invalid inject target",
			cli: func() CliConfig {
				c := baseCliConfig()
				_ = c.SessionCorrelationEnabled.Set("true")
				_ = c.InjectSessionIDTarget.Set("notakey")
				return c
			}(),
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := NewAppConfigFromCliConfig(tc.cli, []string{"echo", "hello"}, tc.environ)
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

func TestDefaultInjectTargetFromEnv(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		environ []string
		want    *InjectTarget
	}{
		{
			name:    "valid URL with trailing slash",
			environ: []string{"CODER_AGENT_URL=https://dev.coder.com/"},
			want:    &InjectTarget{Domain: "dev.coder.com", Path: DefaultAIBridgePath},
		},
		{
			name:    "valid URL without trailing slash",
			environ: []string{"CODER_AGENT_URL=https://dev.coder.com"},
			want:    &InjectTarget{Domain: "dev.coder.com", Path: DefaultAIBridgePath},
		},
		{
			name:    "URL with port", // Ports are ignored in the rules engine, so we strip them here.
			environ: []string{"CODER_AGENT_URL=https://dev.coder.com:8443/"},
			want:    &InjectTarget{Domain: "dev.coder.com", Path: DefaultAIBridgePath},
		},
		{
			name:    "unset variable",
			environ: []string{},
			want:    nil,
		},
		{
			name:    "empty value",
			environ: []string{"CODER_AGENT_URL="},
			want:    nil,
		},
		{
			name:    "no host in URL",
			environ: []string{"CODER_AGENT_URL=not-a-url"},
			want:    nil,
		},
		{
			name:    "other env vars present but not CODER_AGENT_URL",
			environ: []string{"CODER_URL=https://dev.coder.com/", "HOME=/home/user"},
			want:    nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := DefaultInjectTargetFromEnv(tc.environ)
			if tc.want == nil {
				if got != nil {
					t.Errorf("expected nil, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("expected %+v, got nil", tc.want)
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

func TestBuildSessionCorrelation_AgentURLFallback(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		cfg         func() CliConfig
		environ     []string
		wantTargets []InjectTarget
		wantErr     bool
	}{
		{
			name: "enabled, no explicit targets, CODER_AGENT_URL set → auto-derived",
			cfg: func() CliConfig {
				c := baseCliConfig()
				_ = c.SessionCorrelationEnabled.Set("true")
				return c
			},
			environ: []string{"CODER_AGENT_URL=https://dev.coder.com/"},
			wantTargets: []InjectTarget{
				{Domain: "dev.coder.com", Path: DefaultAIBridgePath},
			},
		},
		{
			name: "enabled, no explicit targets, CODER_AGENT_URL absent → error",
			cfg: func() CliConfig {
				c := baseCliConfig()
				_ = c.SessionCorrelationEnabled.Set("true")
				return c
			},
			environ: []string{},
			wantErr: true,
		},
		{
			name: "enabled, explicit target wins over CODER_AGENT_URL",
			cfg: func() CliConfig {
				c := baseCliConfig()
				_ = c.SessionCorrelationEnabled.Set("true")
				_ = c.InjectSessionIDTarget.Set("domain=custom.example.com")
				return c
			},
			environ: []string{"CODER_AGENT_URL=https://dev.coder.com/"},
			wantTargets: []InjectTarget{
				{Domain: "custom.example.com", Path: ""},
			},
		},
		{
			name: "disabled, CODER_AGENT_URL absent → valid (no targets needed)",
			cfg: func() CliConfig {
				return baseCliConfig()
			},
			environ:     []string{},
			wantTargets: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sc, err := buildSessionCorrelation(tc.cfg(), tc.environ)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(sc.InjectTargets) != len(tc.wantTargets) {
				t.Fatalf("InjectTargets len: got %d, want %d",
					len(sc.InjectTargets), len(tc.wantTargets))
			}
			for i := range sc.InjectTargets {
				if sc.InjectTargets[i].Domain != tc.wantTargets[i].Domain {
					t.Errorf("InjectTargets[%d].Domain: got %q, want %q",
						i, sc.InjectTargets[i].Domain, tc.wantTargets[i].Domain)
				}
				if sc.InjectTargets[i].Path != tc.wantTargets[i].Path {
					t.Errorf("InjectTargets[%d].Path: got %q, want %q",
						i, sc.InjectTargets[i].Path, tc.wantTargets[i].Path)
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
	_ = c.JailType.Set("nsjail")
	_ = c.SessionIDHeaderName.Set(DefaultSessionIDHeaderName)
	_ = c.SequenceNumberHeaderName.Set(DefaultSequenceNumberHeaderName)
	return c
}
