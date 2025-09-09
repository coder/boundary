package rules

import (
	"log/slog"
	"testing"
)

func TestNewAllowRule(t *testing.T) {
	tests := []struct {
		name        string
		spec        string
		expectError bool
		expMethods  map[string]bool
		expPattern  string
	}{
		{
			name:        "simple allow rule",
			spec:        "github.com",
			expectError: false,
			expMethods:  nil,
			expPattern:  "github.com",
		},
		{
			name:        "wildcard pattern",
			spec:        "api.*",
			expectError: false,
			expMethods:  nil,
			expPattern:  "api.*",
		},
		{
			name:        "method-specific allow rule",
			spec:        "GET api.github.com",
			expectError: false,
			expMethods:  map[string]bool{"GET": true},
			expPattern:  "api.github.com",
		},
		{
			name:        "multiple methods rule",
			spec:        "GET,POST,PUT api.*",
			expectError: false,
			expMethods:  map[string]bool{"GET": true, "POST": true, "PUT": true},
			expPattern:  "api.*",
		},
		{
			name:        "allow all wildcard",
			spec:        "*",
			expectError: false,
			expMethods:  nil,
			expPattern:  "*",
		},
		{
			name:        "empty spec",
			spec:        "",
			expectError: true,
		},
		{
			name:        "only spaces",
			spec:        "   ",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, err := newAllowRule(tt.spec)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if rule.Pattern != tt.expPattern {
				t.Errorf("expected pattern %s, got %s", tt.expPattern, rule.Pattern)
			}

			if len(rule.Methods) != len(tt.expMethods) {
				t.Errorf("expected %d methods, got %d", len(tt.expMethods), len(rule.Methods))
				return
			}

			for method := range tt.expMethods {
				if !rule.Methods[method] {
					t.Errorf("expected method %s to be allowed", method)
				}
			}
		})
	}
}

func TestParseAllowSpecs(t *testing.T) {
	tests := []struct {
		name         string
		allowStrings []string
		expectError  bool
		expRuleCount int
	}{
		{
			name:         "single allow rule",
			allowStrings: []string{"github.com"},
			expectError:  false,
			expRuleCount: 1,
		},
		{
			name:         "multiple allow rules",
			allowStrings: []string{"github.com", "GET api.*", "POST,PUT upload.*"},
			expectError:  false,
			expRuleCount: 3,
		},
		{
			name:         "empty list",
			allowStrings: []string{},
			expectError:  false,
			expRuleCount: 0,
		},
		{
			name:         "invalid rule in list",
			allowStrings: []string{"github.com", ""},
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := ParseAllowSpecs(tt.allowStrings)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if len(rules) != tt.expRuleCount {
				t.Errorf("expected %d rules, got %d", tt.expRuleCount, len(rules))
			}
		})
	}
}

func TestWildcardMatch(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		text     string
		expected bool
	}{
		// Basic exact matches
		{"exact match", "github.com", "github.com", true},
		{"no match", "github.com", "gitlab.com", false},

		// Wildcard * tests
		{"star matches all", "*", "anything.com", true},
		{"star matches empty", "*", "", true},
		{"prefix star", "github.*", "github.com", true},
		{"prefix star long", "github.*", "github.com/user/repo", true},
		{"suffix star", "*.com", "github.com", true},
		{"suffix star no match", "*.com", "github.org", false},
		{"middle star", "api.*.com", "api.github.com", true},
		{"middle star complex", "api.*.com", "api.v1.github.com", true},
		{"multiple stars", "*github*com*", "api.github.com", true},

		// URL matching
		{"http url exact", "https://api.github.com", "https://api.github.com", true},
		{"http url wildcard", "https://api.github.*", "https://api.github.com", true},
		{"http url prefix", "https://*.github.com", "https://api.github.com", true},

		// Telemetry examples
		{"telemetry wildcard", "telemetry.*", "telemetry.example.com", true},
		{"telemetry no match", "telemetry.*", "api.example.com", false},

		// Case sensitivity
		{"case insensitive", "GitHub.COM", "github.com", true},
		{"case insensitive wildcard", "*.GitHub.COM", "api.github.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := wildcardMatch(tt.pattern, tt.text)
			if result != tt.expected {
				t.Errorf("wildcardMatch(%q, %q) = %v, expected %v", tt.pattern, tt.text, result, tt.expected)
			}
		})
	}
}

func TestRuleMatches(t *testing.T) {
	rule, err := newAllowRule("GET,POST api.github.*")
	if err != nil {
		t.Fatalf("failed to create rule: %v", err)
	}

	tests := []struct {
		name     string
		method   string
		url      string
		expected bool
	}{
		{"matching GET", "GET", "https://api.github.com/user", true},
		{"matching POST", "POST", "https://api.github.com/repos", true},
		{"non-matching method", "PUT", "https://api.github.com/user", false},
		{"non-matching URL", "GET", "https://github.com/user", false},
		{"case insensitive method", "get", "https://api.github.com/user", true},
		{"wildcard match", "GET", "https://api.github.io/docs", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rule.Matches(tt.method, tt.url)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestRuleEngine(t *testing.T) {
	rules := []*Rule{
		{Pattern: "github.com", Methods: nil, Raw: "allow github.com"},
		{Pattern: "api.*", Methods: map[string]bool{"GET": true}, Raw: "allow GET api.*"},
	}

	// Create a logger that discards output during tests
	logger := slog.New(slog.NewTextHandler(nil, &slog.HandlerOptions{
		Level: slog.LevelError + 1, // Higher than any level to suppress all logs
	}))

	engine := NewRuleEngine(rules, logger)

	tests := []struct {
		name     string
		method   string
		url      string
		expected bool
	}{
		{"allow github", "GET", "https://github.com/user/repo", true},
		{"allow api GET", "GET", "https://api.example.com", true},
		{"deny api POST", "POST", "https://api.example.com", false},
		{"deny other", "GET", "https://example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.Evaluate(tt.method, tt.url)
			if result.Allowed != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result.Allowed)
			}
		})
	}
}

func TestRuleEngineWildcardRules(t *testing.T) {
	rules := []*Rule{
		{Pattern: "github.*", Methods: nil, Raw: "allow github.*"},
		{Pattern: "api.*.com", Methods: map[string]bool{"GET": true}, Raw: "allow GET api.*.com"},
	}

	// Create a logger that discards output during tests
	logger := slog.New(slog.NewTextHandler(nil, &slog.HandlerOptions{
		Level: slog.LevelError + 1,
	}))

	engine := NewRuleEngine(rules, logger)

	tests := []struct {
		name     string
		method   string
		url      string
		expected bool
	}{
		{"allow github", "GET", "https://github.com", true},
		{"allow github subdomain", "POST", "https://github.io", true},
		{"allow api GET", "GET", "https://api.example.com", true},
		{"deny api POST", "POST", "https://api.example.com", false},
		{"deny unmatched", "GET", "https://example.org", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.Evaluate(tt.method, tt.url)
			if result.Allowed != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result.Allowed)
			}
		})
	}
}
