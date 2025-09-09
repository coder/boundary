package rules

import (
	"log/slog"
	"testing"
)

func TestNewRule(t *testing.T) {
	tests := []struct {
		name        string
		ruleStr     string
		expectError bool
		expAction   Action
		expMethods  map[string]bool
		expPattern  string
	}{
		{
			name:        "simple allow rule",
			ruleStr:     "allow: github.com",
			expectError: false,
			expAction:   Allow,
			expMethods:  nil,
			expPattern:  "github.com",
		},
		{
			name:        "simple deny rule with wildcard",
			ruleStr:     "deny: telemetry.*",
			expectError: false,
			expAction:   Deny,
			expMethods:  nil,
			expPattern:  "telemetry.*",
		},
		{
			name:        "method-specific allow rule",
			ruleStr:     "allow-get: api.github.com",
			expectError: false,
			expAction:   Allow,
			expMethods:  map[string]bool{"GET": true},
			expPattern:  "api.github.com",
		},
		{
			name:        "multiple methods deny rule",
			ruleStr:     "deny-post-put: upload.*",
			expectError: false,
			expAction:   Deny,
			expMethods:  map[string]bool{"POST": true, "PUT": true},
			expPattern:  "upload.*",
		},
		{
			name:        "wildcard allow all",
			ruleStr:     "allow: *",
			expectError: false,
			expAction:   Allow,
			expMethods:  nil,
			expPattern:  "*",
		},
		{
			name:        "invalid format",
			ruleStr:     "invalid rule",
			expectError: true,
		},
		{
			name:        "invalid action",
			ruleStr:     "invalid: pattern",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, err := newRule(tt.ruleStr)
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

			if rule.Action != tt.expAction {
				t.Errorf("expected action %v, got %v", tt.expAction, rule.Action)
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
	rule, err := newRule("allow-get-post: api.github.*")
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
		{Action: Allow, Pattern: "github.com", Methods: nil, Raw: "allow: github.com"},
		{Action: Deny, Pattern: "*", Methods: nil, Raw: "deny: *"},
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
		expected Action
	}{
		{"allow github", "GET", "https://github.com/user/repo", Allow},
		{"deny other", "GET", "https://example.com", Deny},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.Evaluate(tt.method, tt.url)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestRuleEngineWildcardRules(t *testing.T) {
	rules := []*Rule{
		{Action: Deny, Pattern: "telemetry.*", Methods: nil, Raw: "deny: telemetry.*"},
		{Action: Allow, Pattern: "*", Methods: nil, Raw: "allow: *"},
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
		expected Action
	}{
		{"deny telemetry", "GET", "https://telemetry.example.com", Deny},
		{"allow other", "GET", "https://api.github.com", Allow},
		{"deny telemetry subdomain", "POST", "https://telemetry.analytics.com", Deny},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.Evaluate(tt.method, tt.url)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}