package rulesengine

import (
	"log/slog"
	"testing"
)

func TestEngineMatches(t *testing.T) {
	logger := slog.Default()
	engine := NewRuleEngine(nil, logger)

	tests := []struct {
		name     string
		rule     Rule
		method   string
		url      string
		expected bool
	}{
		// Method pattern tests
		{
			name: "method matches exact",
			rule: Rule{
				MethodPatterns: map[methodPattern]struct{}{methodPattern("GET"): {}},
			},
			method:   "GET",
			url:      "https://example.com/api",
			expected: true,
		},
		{
			name: "method does not match",
			rule: Rule{
				MethodPatterns: map[methodPattern]struct{}{methodPattern("POST"): {}},
			},
			method:   "GET",
			url:      "https://example.com/api",
			expected: false,
		},
		{
			name: "method wildcard matches any",
			rule: Rule{
				MethodPatterns: map[methodPattern]struct{}{methodPattern("*"): {}},
			},
			method:   "PUT",
			url:      "https://example.com/api",
			expected: true,
		},
		{
			name: "no method pattern allows all methods",
			rule: Rule{
				HostPattern: []labelPattern{labelPattern("example"), labelPattern("com")},
			},
			method:   "DELETE",
			url:      "https://example.com/api",
			expected: true,
		},

		// Host pattern tests
		{
			name: "host matches exact",
			rule: Rule{
				HostPattern: []labelPattern{labelPattern("example"), labelPattern("com")},
			},
			method:   "GET",
			url:      "https://example.com/api",
			expected: true,
		},
		{
			name: "host does not match",
			rule: Rule{
				HostPattern: []labelPattern{labelPattern("example"), labelPattern("org")},
			},
			method:   "GET",
			url:      "https://example.com/api",
			expected: false,
		},
		{
			name: "subdomain matches",
			rule: Rule{
				HostPattern: []labelPattern{labelPattern("example"), labelPattern("com")},
			},
			method:   "GET",
			url:      "https://api.example.com/users",
			expected: true,
		},
		{
			name: "host pattern too long",
			rule: Rule{
				HostPattern: []labelPattern{labelPattern("v1"), labelPattern("api"), labelPattern("example"), labelPattern("com")},
			},
			method:   "GET",
			url:      "https://api.example.com/users",
			expected: false,
		},
		{
			name: "host wildcard matches",
			rule: Rule{
				HostPattern: []labelPattern{labelPattern("*"), labelPattern("com")},
			},
			method:   "GET",
			url:      "https://test.com/api",
			expected: true,
		},
		{
			name: "multiple host wildcards",
			rule: Rule{
				HostPattern: []labelPattern{labelPattern("*"), labelPattern("*")},
			},
			method:   "GET",
			url:      "https://api.example.com/users",
			expected: true,
		},

		// Path pattern tests
		{
			name: "path matches exact",
			rule: Rule{
				PathPattern: []segmentPattern{segmentPattern("api"), segmentPattern("users")},
			},
			method:   "GET",
			url:      "https://example.com/api/users",
			expected: true,
		},
		{
			name: "path does not match",
			rule: Rule{
				PathPattern: []segmentPattern{segmentPattern("api"), segmentPattern("posts")},
			},
			method:   "GET",
			url:      "https://example.com/api/users",
			expected: false,
		},
		{
			name: "subpath matches",
			rule: Rule{
				PathPattern: []segmentPattern{segmentPattern("api")},
			},
			method:   "GET",
			url:      "https://example.com/api/users/123",
			expected: true,
		},
		{
			name: "path pattern too long",
			rule: Rule{
				PathPattern: []segmentPattern{segmentPattern("api"), segmentPattern("v1"), segmentPattern("users"), segmentPattern("profile")},
			},
			method:   "GET",
			url:      "https://example.com/api/v1/users",
			expected: false,
		},
		{
			name: "path wildcard matches",
			rule: Rule{
				PathPattern: []segmentPattern{segmentPattern("api"), segmentPattern("*"), segmentPattern("profile")},
			},
			method:   "GET",
			url:      "https://example.com/api/users/profile",
			expected: true,
		},
		{
			name: "multiple path wildcards",
			rule: Rule{
				PathPattern: []segmentPattern{segmentPattern("*"), segmentPattern("*")},
			},
			method:   "GET",
			url:      "https://example.com/api/users/123",
			expected: true,
		},

		// Combined pattern tests
		{
			name: "all patterns match",
			rule: Rule{
				MethodPatterns: map[methodPattern]struct{}{methodPattern("POST"): {}},
				HostPattern:    []labelPattern{labelPattern("api"), labelPattern("com")},
				PathPattern:    []segmentPattern{segmentPattern("users")},
			},
			method:   "POST",
			url:      "https://api.com/users",
			expected: true,
		},
		{
			name: "method fails combined test",
			rule: Rule{
				MethodPatterns: map[methodPattern]struct{}{methodPattern("POST"): {}},
				HostPattern:    []labelPattern{labelPattern("api"), labelPattern("com")},
				PathPattern:    []segmentPattern{segmentPattern("users")},
			},
			method:   "GET",
			url:      "https://api.com/users",
			expected: false,
		},
		{
			name: "host fails combined test",
			rule: Rule{
				MethodPatterns: map[methodPattern]struct{}{methodPattern("POST"): {}},
				HostPattern:    []labelPattern{labelPattern("api"), labelPattern("org")},
				PathPattern:    []segmentPattern{segmentPattern("users")},
			},
			method:   "POST",
			url:      "https://api.com/users",
			expected: false,
		},
		{
			name: "path fails combined test",
			rule: Rule{
				MethodPatterns: map[methodPattern]struct{}{methodPattern("POST"): {}},
				HostPattern:    []labelPattern{labelPattern("api"), labelPattern("com")},
				PathPattern:    []segmentPattern{segmentPattern("posts")},
			},
			method:   "POST",
			url:      "https://api.com/users",
			expected: false,
		},
		{
			name: "all wildcards match",
			rule: Rule{
				MethodPatterns: map[methodPattern]struct{}{methodPattern("*"): {}},
				HostPattern:    []labelPattern{labelPattern("*"), labelPattern("*")},
				PathPattern:    []segmentPattern{segmentPattern("*"), segmentPattern("*")},
			},
			method:   "PATCH",
			url:      "https://test.example.com/api/users/123",
			expected: true,
		},

		// Edge cases
		{
			name:     "empty rule matches everything",
			rule:     Rule{},
			method:   "GET",
			url:      "https://example.com/api/users",
			expected: true,
		},
		{
			name: "invalid URL",
			rule: Rule{
				HostPattern: []labelPattern{labelPattern("example"), labelPattern("com")},
			},
			method:   "GET",
			url:      "not-a-valid-url",
			expected: false,
		},
		{
			name: "root path",
			rule: Rule{
				PathPattern: []segmentPattern{},
			},
			method:   "GET",
			url:      "https://example.com/",
			expected: true,
		},
		{
			name: "localhost host",
			rule: Rule{
				HostPattern: []labelPattern{labelPattern("localhost")},
			},
			method:   "GET",
			url:      "http://localhost:8080/api",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.matches(tt.rule, tt.method, tt.url)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}
