package config

import (
	"testing"
)

func TestParseInjectTarget_ViaValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:  "domain only",
			input: "domain=dev.coder.com",
		},
		{
			name:  "domain and path",
			input: "domain=dev.coder.com path=/api/v2/aibridge/*",
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "missing domain",
			input:   "path=/api/*",
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

			cfg := SessionCorrelationConfig{
				Enabled:       true,
				InjectTargets: []string{tc.input},
			}
			err := ValidateSessionCorrelation(cfg)
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
			name: "enabled with targets",
			cfg: SessionCorrelationConfig{
				Enabled:       true,
				InjectTargets: []string{"domain=dev.coder.com"},
			},
		},
		{
			name: "enabled with no targets",
			cfg: SessionCorrelationConfig{
				Enabled:       true,
				InjectTargets: nil,
			},
			wantErr: true,
		},
		{
			name: "enabled with empty targets slice",
			cfg: SessionCorrelationConfig{
				Enabled:       true,
				InjectTargets: []string{},
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
		name        string
		cli         CliConfig
		environ     []string
		wantEnabled bool
		wantTargets []string
		wantErr     bool
	}{
		{
			name:        "defaults when not configured",
			cli:         baseCliConfig(),
			wantEnabled: false,
			wantTargets: nil,
		},
		{
			name: "enabled with inject targets",
			cli: func() CliConfig {
				c := baseCliConfig()
				_ = c.SessionCorrelationEnabled.Set("true")
				_ = c.InjectSessionIDTarget.Set("domain=dev.coder.com path=/api/v2/aibridge/*")
				return c
			}(),
			wantEnabled: true,
			wantTargets: []string{"domain=dev.coder.com path=/api/v2/aibridge/*"},
		},
		{
			name: "enabled with no targets, CODER_AGENT_URL set -> auto-derived",
			cli: func() CliConfig {
				c := baseCliConfig()
				_ = c.SessionCorrelationEnabled.Set("true")
				return c
			}(),
			environ:     []string{"CODER_AGENT_URL=https://dev.coder.com/"},
			wantEnabled: true,
			wantTargets: []string{"domain=dev.coder.com path=" + DefaultAIBridgePath},
		},
		{
			name: "enabled with no targets, CODER_AGENT_URL absent -> error",
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
			if sc.Enabled != tc.wantEnabled {
				t.Errorf("Enabled: got %v, want %v", sc.Enabled, tc.wantEnabled)
			}
			if len(sc.InjectTargets) != len(tc.wantTargets) {
				t.Fatalf("InjectTargets len: got %d, want %d",
					len(sc.InjectTargets), len(tc.wantTargets))
			}
			for i := range sc.InjectTargets {
				if sc.InjectTargets[i] != tc.wantTargets[i] {
					t.Errorf("InjectTargets[%d]: got %q, want %q",
						i, sc.InjectTargets[i], tc.wantTargets[i])
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
		want    string
	}{
		{
			name:    "valid URL with trailing slash",
			environ: []string{"CODER_AGENT_URL=https://dev.coder.com/"},
			want:    "domain=dev.coder.com path=" + DefaultAIBridgePath,
		},
		{
			name:    "valid URL without trailing slash",
			environ: []string{"CODER_AGENT_URL=https://dev.coder.com"},
			want:    "domain=dev.coder.com path=" + DefaultAIBridgePath,
		},
		{
			name:    "URL with port",
			environ: []string{"CODER_AGENT_URL=https://dev.coder.com:8443/"},
			want:    "domain=dev.coder.com path=" + DefaultAIBridgePath,
		},
		{
			name:    "unset variable",
			environ: []string{},
			want:    "",
		},
		{
			name:    "empty value",
			environ: []string{"CODER_AGENT_URL="},
			want:    "",
		},
		{
			name:    "no host in URL",
			environ: []string{"CODER_AGENT_URL=not-a-url"},
			want:    "",
		},
		{
			name:    "other env vars present but not CODER_AGENT_URL",
			environ: []string{"CODER_URL=https://dev.coder.com/", "HOME=/home/user"},
			want:    "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := DefaultInjectTargetFromEnv(tc.environ)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBuildSessionCorrelation_TargetMerge(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		cfg         func() CliConfig
		wantTargets []string
	}{
		{
			name: "YAML targets only",
			cfg: func() CliConfig {
				c := baseCliConfig()
				_ = c.SessionCorrelationEnabled.Set("true")
				_ = c.InjectSessionIDTargets.Set("domain=yaml.example.com path=/yaml/*")
				return c
			},
			wantTargets: []string{
				"domain=yaml.example.com path=/yaml/*",
			},
		},
		{
			name: "CLI targets only",
			cfg: func() CliConfig {
				c := baseCliConfig()
				_ = c.SessionCorrelationEnabled.Set("true")
				_ = c.InjectSessionIDTarget.Set("domain=cli.example.com path=/cli/*")
				return c
			},
			wantTargets: []string{
				"domain=cli.example.com path=/cli/*",
			},
		},
		{
			name: "YAML and CLI targets merged, YAML comes first",
			cfg: func() CliConfig {
				c := baseCliConfig()
				_ = c.SessionCorrelationEnabled.Set("true")
				_ = c.InjectSessionIDTargets.Set("domain=yaml.example.com path=/yaml/*")
				_ = c.InjectSessionIDTarget.Set("domain=cli.example.com path=/cli/*")
				return c
			},
			wantTargets: []string{
				"domain=yaml.example.com path=/yaml/*",
				"domain=cli.example.com path=/cli/*",
			},
		},
		{
			name: "multiple from each source are all preserved",
			cfg: func() CliConfig {
				c := baseCliConfig()
				_ = c.SessionCorrelationEnabled.Set("true")
				_ = c.InjectSessionIDTargets.Set("domain=yaml1.example.com")
				_ = c.InjectSessionIDTargets.Set("domain=yaml2.example.com")
				_ = c.InjectSessionIDTarget.Set("domain=cli1.example.com")
				_ = c.InjectSessionIDTarget.Set("domain=cli2.example.com")
				return c
			},
			wantTargets: []string{
				"domain=yaml1.example.com",
				"domain=yaml2.example.com",
				"domain=cli1.example.com",
				"domain=cli2.example.com",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sc, err := buildSessionCorrelation(tc.cfg(), []string{})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(sc.InjectTargets) != len(tc.wantTargets) {
				t.Fatalf("InjectTargets len: got %d, want %d",
					len(sc.InjectTargets), len(tc.wantTargets))
			}
			for i := range sc.InjectTargets {
				if sc.InjectTargets[i] != tc.wantTargets[i] {
					t.Errorf("InjectTargets[%d]: got %q, want %q",
						i, sc.InjectTargets[i], tc.wantTargets[i])
				}
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
		wantTargets []string
		wantErr     bool
	}{
		{
			name: "enabled, no explicit targets, CODER_AGENT_URL set -> auto-derived",
			cfg: func() CliConfig {
				c := baseCliConfig()
				_ = c.SessionCorrelationEnabled.Set("true")
				return c
			},
			environ: []string{"CODER_AGENT_URL=https://dev.coder.com/"},
			wantTargets: []string{
				"domain=dev.coder.com path=" + DefaultAIBridgePath,
			},
		},
		{
			name: "enabled, no explicit targets, CODER_AGENT_URL absent -> error",
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
			wantTargets: []string{
				"domain=custom.example.com",
			},
		},
		{
			name: "disabled, CODER_AGENT_URL absent -> valid (no targets needed)",
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
				if sc.InjectTargets[i] != tc.wantTargets[i] {
					t.Errorf("InjectTargets[%d]: got %q, want %q",
						i, sc.InjectTargets[i], tc.wantTargets[i])
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
	return c
}
