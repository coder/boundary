package rules

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"
)

func TestRule_Matches_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		rule     *Rule
		method   string
		url      string
		expected bool
	}{
		{
			name: "empty URL with wildcard pattern",
			rule: &Rule{
				Pattern: "*",
				Methods: nil,
				Raw:     "allow *",
			},
			method:   "GET",
			url:      "",
			expected: true,
		},
		{
			name: "domain-only URL matching",
			rule: &Rule{
				Pattern: "example.com",
				Methods: nil,
				Raw:     "allow example.com",
			},
			method:   "GET",
			url:      "https://example.com", // Should match just domain
			expected: true,
		},
		{
			name: "domain with path matching",
			rule: &Rule{
				Pattern: "example.com",
				Methods: nil,
				Raw:     "allow example.com",
			},
			method:   "GET",
			url:      "https://example.com/path", // Should match domain part
			expected: true,
		},
		{
			name: "no protocol URL matching",
			rule: &Rule{
				Pattern: "example.com/api",
				Methods: nil,
				Raw:     "allow example.com/api",
			},
			method:   "POST",
			url:      "example.com/api", // URL without protocol
			expected: true,
		},
		{
			name: "HTTP protocol with pattern",
			rule: &Rule{
				Pattern: "http://example.com",
				Methods: nil,
				Raw:     "allow http://example.com",
			},
			method:   "GET",
			url:      "http://example.com",
			expected: true,
		},
		{
			name: "HTTPS protocol with pattern",
			rule: &Rule{
				Pattern: "https://api.example.com",
				Methods: nil,
				Raw:     "allow https://api.example.com",
			},
			method:   "GET",
			url:      "https://api.example.com",
			expected: true,
		},
		{
			name: "method restriction with uppercase",
			rule: &Rule{
				Pattern: "api.example.com",
				Methods: map[string]bool{"GET": true, "POST": true},
				Raw:     "allow GET,POST api.example.com",
			},
			method:   "get", // lowercase method should work
			url:      "https://api.example.com",
			expected: true,
		},
		{
			name: "method restriction with disallowed method",
			rule: &Rule{
				Pattern: "api.example.com",
				Methods: map[string]bool{"GET": true},
				Raw:     "allow GET api.example.com",
			},
			method:   "DELETE",
			url:      "https://api.example.com",
			expected: false,
		},
		{
			name: "domain without path in URL",
			rule: &Rule{
				Pattern: "example.com",
				Methods: nil,
				Raw:     "allow example.com",
			},
			method:   "GET",
			url:      "https://example.com", // No path, just domain
			expected: true,
		},
		{
			name: "domain matching with port",
			rule: &Rule{
				Pattern: "localhost:8080",
				Methods: nil,
				Raw:     "allow localhost:8080",
			},
			method:   "GET",
			url:      "http://localhost:8080/api",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.rule.Matches(tt.method, tt.url)
			if result != tt.expected {
				t.Errorf("rule.Matches(%q, %q) = %v, expected %v", tt.method, tt.url, result, tt.expected)
			}
		})
	}
}

func TestNewAllowRule_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		spec        string
		expectError bool
		errorMsg    string
		expMethods  map[string]bool
		expPattern  string
	}{
		{
			name:        "spec with only spaces",
			spec:        "   \t  ",
			expectError: true,
			errorMsg:    "empty",
		},
		{
			name:        "spec with methods and empty pattern",
			spec:        "GET,POST ",
			expectError: false, // Trailing space is treated as pattern
			expMethods:  nil,
			expPattern:  "GET,POST", // Whitespace gets trimmed
		},
		{
			name:        "spec with methods and only whitespace pattern",
			spec:        "GET,POST   \t  ",
			expectError: false, // Whitespace is treated as pattern
			expMethods:  nil,
			expPattern:  "GET,POST", // Whitespace gets trimmed
		},
		{
			name:        "spec with invalid characters in methods",
			spec:        "GET,123 example.com", // numbers in method
			expectError: false,
			expMethods:  nil,
			expPattern:  "GET,123 example.com",
		},
		{
			name:        "spec with mixed case methods",
			spec:        "get,POST,Head example.com",
			expectError: false,
			expMethods:  map[string]bool{"GET": true, "POST": true, "HEAD": true},
			expPattern:  "example.com",
		},
		{
			name:        "spec with empty method in list",
			spec:        "GET,,POST example.com",
			expectError: false,
			expMethods:  map[string]bool{"GET": true, "POST": true}, // empty method skipped
			expPattern:  "example.com",
		},
		{
			name:        "spec with tab separator",
			spec:        "GET\texample.com",
			expectError: false,
			expMethods:  map[string]bool{"GET": true},
			expPattern:  "example.com",
		},
		{
			name:        "spec with multiple spaces",
			spec:        "GET,POST    example.com",
			expectError: false,
			expMethods:  map[string]bool{"GET": true, "POST": true},
			expPattern:  "example.com",
		},
		{
			name:        "spec without space (pattern only)",
			spec:        "example.com/api/v1",
			expectError: false,
			expMethods:  nil,
			expPattern:  "example.com/api/v1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, err := newAllowRule(tt.spec)
			
			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
					return
				}
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error to contain %q, got: %v", tt.errorMsg, err)
				}
				return
			}
			
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			
			if rule.Pattern != tt.expPattern {
				t.Errorf("expected pattern %q, got %q", tt.expPattern, rule.Pattern)
			}
			
			if len(rule.Methods) != len(tt.expMethods) {
				t.Errorf("expected %d methods, got %d", len(tt.expMethods), len(rule.Methods))
				return
			}
			
			for method := range tt.expMethods {
				if !rule.Methods[method] {
					t.Errorf("expected method %q to be allowed", method)
				}
			}
		})
	}
}

func TestWildcardMatch_ComplexCases(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		text     string
		expected bool
	}{
		{
			name:     "pattern longer than text",
			pattern:  "verylongpattern",
			text:     "short",
			expected: false,
		},
		{
			name:     "pattern ending with multiple stars",
			pattern:  "api***",
			text:     "api.example.com",
			expected: true,
		},
		{
			name:     "empty pattern and text",
			pattern:  "",
			text:     "",
			expected: true,
		},
		{
			name:     "pattern with star at end, no match",
			pattern:  "xyz*",
			text:     "abc",
			expected: false,
		},
		{
			name:     "multiple consecutive stars",
			pattern:  "a**b",
			text:     "a123b",
			expected: true,
		},
		{
			name:     "star at beginning and end",
			pattern:  "*middle*",
			text:     "prefix_middle_suffix",
			expected: true,
		},
		{
			name:     "complex pattern with multiple stars",
			pattern:  "*api*v*",
			text:     "https://api.example.com/v1/users",
			expected: true,
		},
		{
			name:     "pattern only stars",
			pattern:  "***",
			text:     "anything",
			expected: true,
		},
		{
			name:     "text longer than pattern with stars",
			pattern:  "a*",
			text:     "averyverylongtext",
			expected: true,
		},
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

func TestRuleEngine_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		rules    []*Rule
		method   string
		url      string
		expected Result
	}{
		{
			name:  "empty rules list",
			rules: []*Rule{},
			method: "GET",
			url:    "https://example.com",
			expected: Result{
				Allowed: false,
				Rule:    "",
			},
		},
		{
			name:  "nil rules list",
			rules: nil,
			method: "GET",
			url:    "https://example.com",
			expected: Result{
				Allowed: false,
				Rule:    "",
			},
		},
		{
			name: "multiple rules with first match",
			rules: []*Rule{
				{Pattern: "example.com", Methods: nil, Raw: "allow example.com"},
				{Pattern: "*", Methods: nil, Raw: "allow *"},
			},
			method: "GET",
			url:    "https://example.com",
			expected: Result{
				Allowed: true,
				Rule:    "allow example.com",
			},
		},
		{
			name: "rules with method restrictions",
			rules: []*Rule{
				{Pattern: "api.example.com", Methods: map[string]bool{"POST": true}, Raw: "allow POST api.example.com"},
				{Pattern: "api.example.com", Methods: nil, Raw: "allow api.example.com"},
			},
			method: "GET",
			url:    "https://api.example.com",
			expected: Result{
				Allowed: true,
				Rule:    "allow api.example.com",
			},
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelError + 1, // Suppress logs during test
	}))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := NewRuleEngine(tt.rules, logger)
			result := engine.Evaluate(tt.method, tt.url)
			
			if result.Allowed != tt.expected.Allowed {
				t.Errorf("expected Allowed=%v, got %v", tt.expected.Allowed, result.Allowed)
			}
			if result.Rule != tt.expected.Rule {
				t.Errorf("expected Rule=%q, got %q", tt.expected.Rule, result.Rule)
			}
		})
	}
}

func TestParseAllowSpecs_EdgeCases(t *testing.T) {
	tests := []struct {
		name         string
		allowStrings []string
		expectError  bool
		errorMsg     string
		expRuleCount int
	}{
		{
			name:         "nil input",
			allowStrings: nil,
			expectError:  false,
			expRuleCount: 0,
		},
		{
			name:         "empty strings in list",
			allowStrings: []string{"github.com", "", "api.example.com"},
			expectError:  true,
			errorMsg:     "empty",
		},
		{
			name:         "whitespace only string",
			allowStrings: []string{"github.com", "   \t  "},
			expectError:  true,
			errorMsg:     "empty",
		},
		{
			name:         "mixed valid and invalid",
			allowStrings: []string{"github.com", "GET,POST "},
			expectError:  false, // "GET,POST " is treated as pattern, not error
			expRuleCount: 2,
		},
		{
			name:         "large number of rules",
			allowStrings: func() []string {
				rules := make([]string, 1000)
				for i := range rules {
					rules[i] = "example.com"
				}
				return rules
			}(),
			expectError:  false,
			expRuleCount: 1000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := ParseAllowSpecs(tt.allowStrings)
			
			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
					return
				}
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error to contain %q, got: %v", tt.errorMsg, err)
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

// Performance/stress tests
func TestWildcardMatch_Performance(t *testing.T) {
	// Test with complex patterns that might cause exponential backtracking
	complexTests := []struct {
		pattern string
		text    string
	}{
		{"*a*b*c*d*e*f*g*", "this_is_a_very_long_text_with_abcdefg_somewhere"},
		{"a*b*c*d*e*f*g*h*i*j*", "abcdefghij"},
		{"*" + strings.Repeat("a*", 10), "aaaaaaaaaa"},
	}

	for _, test := range complexTests {
		t.Run("complex_pattern", func(t *testing.T) {
			// Should complete quickly without exponential blowup
			start := time.Now()
			_ = wildcardMatch(test.pattern, test.text)
			duration := time.Since(start)
			
			// Should complete within reasonable time
			if duration > 100*time.Millisecond {
				t.Errorf("wildcard matching took too long: %v", duration)
			}
		})
	}
}

// Integration test with real URL patterns
func TestIntegrationWithRealPatterns(t *testing.T) {
	realPatterns := []struct {
		pattern string
		urls    []string
		should  []bool
	}{
		{
			pattern: "*.github.com",
			urls:    []string{"https://api.github.com", "https://github.com", "https://raw.githubusercontent.com"},
			should:  []bool{true, false, false}, // Only api.github.com should match
		},
		{
			pattern: "github.com/*",
			urls:    []string{"https://github.com/user/repo", "https://github.com", "https://api.github.com"},
			should:  []bool{true, false, false}, // github.com/* doesn't match bare github.com
		},
		{
			pattern: "*/api/*",
			urls:    []string{"https://example.com/api/v1", "https://test.org/api/data", "https://example.com/web"},
			should:  []bool{true, true, false},
		},
	}

	for i, test := range realPatterns {
		t.Run(fmt.Sprintf("pattern_%d", i), func(t *testing.T) {
			rule := &Rule{
				Pattern: test.pattern,
				Methods: nil,
				Raw:     "allow " + test.pattern,
			}
			
			for j, url := range test.urls {
				result := rule.Matches("GET", url)
				expected := test.should[j]
				
				if result != expected {
					t.Errorf("pattern %q with URL %q: expected %v, got %v", 
						test.pattern, url, expected, result)
				}
			}
		})
	}
}
