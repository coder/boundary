package rules

import "testing"

func TestParseHTTPToken(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		expectedToken  methodPattern
		expectedRemain string
		expectError    bool
	}{
		{
			name:           "empty string",
			input:          "",
			expectedToken:  "",
			expectedRemain: "",
			expectError:    true,
		},
		{
			name:           "simple method GET",
			input:          "GET",
			expectedToken:  "GET",
			expectedRemain: "",
			expectError:    false,
		},
		{
			name:           "simple method POST",
			input:          "POST",
			expectedToken:  "POST",
			expectedRemain: "",
			expectError:    false,
		},
		{
			name:           "method with trailing space",
			input:          "GET ",
			expectedToken:  "GET",
			expectedRemain: " ",
			expectError:    false,
		},
		{
			name:           "method with trailing content",
			input:          "POST /api/users",
			expectedToken:  "POST",
			expectedRemain: " /api/users",
			expectError:    false,
		},
		{
			name:           "all valid special characters",
			input:          "!#$%&'*+-.^_`|~",
			expectedToken:  "!#$%&'*+-.^_`|~",
			expectedRemain: "",
			expectError:    false,
		},
		{
			name:           "alphanumeric token",
			input:          "ABC123xyz",
			expectedToken:  "ABC123xyz",
			expectedRemain: "",
			expectError:    false,
		},
		{
			name:           "token with invalid character",
			input:          "GET@test",
			expectedToken:  "GET",
			expectedRemain: "@test",
			expectError:    false,
		},
		{
			name:           "token starting with invalid character",
			input:          "@GET",
			expectedToken:  "",
			expectedRemain: "@GET",
			expectError:    false,
		},
		{
			name:           "single character token",
			input:          "A",
			expectedToken:  "A",
			expectedRemain: "",
			expectError:    false,
		},
		{
			name:           "token with underscore and dash",
			input:          "CUSTOM-METHOD_1",
			expectedToken:  "CUSTOM-METHOD_1",
			expectedRemain: "",
			expectError:    false,
		},
		{
			name:           "token stops at comma",
			input:          "GET,POST",
			expectedToken:  "GET",
			expectedRemain: ",POST",
			expectError:    false,
		},
		{
			name:           "token stops at semicolon",
			input:          "GET;charset=utf-8",
			expectedToken:  "GET",
			expectedRemain: ";charset=utf-8",
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, remain, err := parseMethodPattern(tt.input)

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

			if token != tt.expectedToken {
				t.Errorf("expected token %q, got %q", tt.expectedToken, token)
			}

			if remain != tt.expectedRemain {
				t.Errorf("expected remaining %q, got %q", tt.expectedRemain, remain)
			}
		})
	}
}

func TestParseHost(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		expectedHost []labelPattern
		expectedRest string
		expectError  bool
	}{
		{
			name:         "empty string",
			input:        "",
			expectedHost: nil,
			expectedRest: "",
			expectError:  true,
		},
		{
			name:         "simple domain",
			input:        "google.com",
			expectedHost: []labelPattern{labelPattern("google"), labelPattern("com")},
			expectedRest: "",
			expectError:  false,
		},
		{
			name:         "subdomain",
			input:        "api.google.com",
			expectedHost: []labelPattern{labelPattern("api"), labelPattern("google"), labelPattern("com")},
			expectedRest: "",
			expectError:  false,
		},
		{
			name:         "single label",
			input:        "localhost",
			expectedHost: []labelPattern{labelPattern("localhost")},
			expectedRest: "",
			expectError:  false,
		},
		{
			name:         "domain with trailing content",
			input:        "example.org/path",
			expectedHost: []labelPattern{labelPattern("example"), labelPattern("org")},
			expectedRest: "/path",
			expectError:  false,
		},
		{
			name:         "domain with port",
			input:        "localhost:8080",
			expectedHost: []labelPattern{labelPattern("localhost")},
			expectedRest: ":8080",
			expectError:  false,
		},
		{
			name:         "numeric labels",
			input:        "192.168.1.1",
			expectedHost: []labelPattern{labelPattern("192"), labelPattern("168"), labelPattern("1"), labelPattern("1")},
			expectedRest: "",
			expectError:  false,
		},
		{
			name:         "hyphenated domain",
			input:        "my-site.example-domain.co.uk",
			expectedHost: []labelPattern{labelPattern("my-site"), labelPattern("example-domain"), labelPattern("co"), labelPattern("uk")},
			expectedRest: "",
			expectError:  false,
		},
		{
			name:         "alphanumeric labels",
			input:        "a1b2c3.test123.com",
			expectedHost: []labelPattern{labelPattern("a1b2c3"), labelPattern("test123"), labelPattern("com")},
			expectedRest: "",
			expectError:  false,
		},
		{
			name:         "starts with hyphen",
			input:        "-invalid.com",
			expectedHost: nil,
			expectedRest: "",
			expectError:  true,
		},
		{
			name:         "ends with hyphen",
			input:        "invalid-.com",
			expectedHost: nil,
			expectedRest: "",
			expectError:  true,
		},
		{
			name:         "label ends with hyphen",
			input:        "test.invalid-.com",
			expectedHost: nil,
			expectedRest: "",
			expectError:  true,
		},
		{
			name:         "invalid character",
			input:        "test@example.com",
			expectedHost: []labelPattern{labelPattern("test")},
			expectedRest: "@example.com",
			expectError:  false,
		},
		{
			name:         "empty label",
			input:        "test..com",
			expectedHost: nil,
			expectedRest: "",
			expectError:  true,
		},
		{
			name:         "trailing dot",
			input:        "example.com.",
			expectedHost: nil,
			expectedRest: "",
			expectError:  true,
		},
		{
			name:         "single character labels",
			input:        "a.b.c",
			expectedHost: []labelPattern{labelPattern("a"), labelPattern("b"), labelPattern("c")},
			expectedRest: "",
			expectError:  false,
		},
		{
			name:         "mixed case",
			input:        "Example.COM",
			expectedHost: []labelPattern{labelPattern("Example"), labelPattern("COM")},
			expectedRest: "",
			expectError:  false,
		},
		{
			name:         "wildcard subdomain",
			input:        "*.example.com",
			expectedHost: []labelPattern{labelPattern("*"), labelPattern("example"), labelPattern("com")},
			expectedRest: "",
			expectError:  false,
		},
		{
			name:         "wildcard domain",
			input:        "api.*",
			expectedHost: []labelPattern{labelPattern("api"), labelPattern("*")},
			expectedRest: "",
			expectError:  false,
		},
		{
			name:         "multiple wildcards",
			input:        "*.*.com",
			expectedHost: []labelPattern{labelPattern("*"), labelPattern("*"), labelPattern("com")},
			expectedRest: "",
			expectError:  false,
		},
		{
			name:         "wildcard with trailing content",
			input:        "*.example.com/path",
			expectedHost: []labelPattern{labelPattern("*"), labelPattern("example"), labelPattern("com")},
			expectedRest: "/path",
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hostResult, rest, err := parseHostPattern(tt.input)

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

			if len(hostResult) != len(tt.expectedHost) {
				t.Errorf("expected host length %d, got %d", len(tt.expectedHost), len(hostResult))
				return
			}

			for i, expectedLabel := range tt.expectedHost {
				if hostResult[i] != expectedLabel {
					t.Errorf("expected label[%d] %q, got %q", i, expectedLabel, hostResult[i])
				}
			}

			if rest != tt.expectedRest {
				t.Errorf("expected remaining %q, got %q", tt.expectedRest, rest)
			}
		})
	}
}

func TestParseLabel(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectedLabel labelPattern
		expectedRest  string
		expectError   bool
	}{
		{
			name:          "empty string",
			input:         "",
			expectedLabel: "",
			expectedRest:  "",
			expectError:   true,
		},
		{
			name:          "simple label",
			input:         "test",
			expectedLabel: "test",
			expectedRest:  "",
			expectError:   false,
		},
		{
			name:          "label with dot",
			input:         "test.com",
			expectedLabel: "test",
			expectedRest:  ".com",
			expectError:   false,
		},
		{
			name:          "label with hyphen",
			input:         "my-site",
			expectedLabel: "my-site",
			expectedRest:  "",
			expectError:   false,
		},
		{
			name:          "alphanumeric label",
			input:         "test123",
			expectedLabel: "test123",
			expectedRest:  "",
			expectError:   false,
		},
		{
			name:          "starts with hyphen",
			input:         "-invalid",
			expectedLabel: "",
			expectedRest:  "",
			expectError:   true,
		},
		{
			name:          "ends with hyphen",
			input:         "invalid-",
			expectedLabel: "",
			expectedRest:  "",
			expectError:   true,
		},
		{
			name:          "ends with hyphen followed by dot",
			input:         "invalid-.com",
			expectedLabel: "",
			expectedRest:  "",
			expectError:   true,
		},
		{
			name:          "single character",
			input:         "a",
			expectedLabel: "a",
			expectedRest:  "",
			expectError:   false,
		},
		{
			name:          "numeric label",
			input:         "123",
			expectedLabel: "123",
			expectedRest:  "",
			expectError:   false,
		},
		{
			name:          "mixed case",
			input:         "Test",
			expectedLabel: "Test",
			expectedRest:  "",
			expectError:   false,
		},
		{
			name:          "invalid character",
			input:         "test@invalid",
			expectedLabel: "test",
			expectedRest:  "@invalid",
			expectError:   false,
		},
		{
			name:          "starts with number",
			input:         "1test",
			expectedLabel: "1test",
			expectedRest:  "",
			expectError:   false,
		},
		{
			name:          "label with trailing slash",
			input:         "api/path",
			expectedLabel: "api",
			expectedRest:  "/path",
			expectError:   false,
		},
		{
			name:          "wildcard label",
			input:         "*",
			expectedLabel: "*",
			expectedRest:  "",
			expectError:   false,
		},
		{
			name:          "wildcard with dot",
			input:         "*.com",
			expectedLabel: "*",
			expectedRest:  ".com",
			expectError:   false,
		},
		{
			name:          "wildcard with trailing content",
			input:         "*/path",
			expectedLabel: "*",
			expectedRest:  "/path",
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			labelResult, rest, err := parseLabelPattern(tt.input)

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

			if labelResult != tt.expectedLabel {
				t.Errorf("expected label %q, got %q", tt.expectedLabel, labelResult)
			}

			if rest != tt.expectedRest {
				t.Errorf("expected remaining %q, got %q", tt.expectedRest, rest)
			}
		})
	}
}

func TestParsePathSegment(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		expectedSegment segmentPattern
		expectedRest    string
		expectError     bool
	}{
		{
			name:            "empty string",
			input:           "",
			expectedSegment: "",
			expectedRest:    "",
			expectError:     false,
		},
		{
			name:            "simple segment",
			input:           "api",
			expectedSegment: "api",
			expectedRest:    "",
			expectError:     false,
		},
		{
			name:            "segment with slash",
			input:           "api/users",
			expectedSegment: "api",
			expectedRest:    "/users",
			expectError:     false,
		},
		{
			name:            "segment with unreserved chars",
			input:           "my-file.txt_version~1",
			expectedSegment: "my-file.txt_version~1",
			expectedRest:    "",
			expectError:     false,
		},
		{
			name:            "segment with sub-delims",
			input:           "filter='test'&sort=name",
			expectedSegment: "filter='test'&sort=name",
			expectedRest:    "",
			expectError:     false,
		},
		{
			name:            "segment with colon and at",
			input:           "user:password@domain",
			expectedSegment: "user:password@domain",
			expectedRest:    "",
			expectError:     false,
		},
		{
			name:            "percent encoded segment",
			input:           "hello%20world",
			expectedSegment: "hello%20world",
			expectedRest:    "",
			expectError:     false,
		},
		{
			name:            "multiple percent encoded",
			input:           "%3Fkey%3Dvalue%26other%3D123",
			expectedSegment: "%3Fkey%3Dvalue%26other%3D123",
			expectedRest:    "",
			expectError:     false,
		},
		{
			name:            "invalid percent encoding incomplete",
			input:           "test%2",
			expectedSegment: "test",
			expectedRest:    "%2",
			expectError:     false,
		},
		{
			name:            "invalid percent encoding non-hex",
			input:           "test%ZZ",
			expectedSegment: "test",
			expectedRest:    "%ZZ",
			expectError:     false,
		},
		{
			name:            "segment stops at space",
			input:           "test hello",
			expectedSegment: "test",
			expectedRest:    " hello",
			expectError:     false,
		},
		{
			name:            "segment with question mark stops",
			input:           "path?query=value",
			expectedSegment: "path",
			expectedRest:    "?query=value",
			expectError:     false,
		},
		{
			name:            "segment with hash stops",
			input:           "path#fragment",
			expectedSegment: "path",
			expectedRest:    "#fragment",
			expectError:     false,
		},
		{
			name:            "numeric segment",
			input:           "123456",
			expectedSegment: "123456",
			expectedRest:    "",
			expectError:     false,
		},
		{
			name:            "mixed alphanumeric",
			input:           "abc123XYZ",
			expectedSegment: "abc123XYZ",
			expectedRest:    "",
			expectError:     false,
		},
		{
			name:            "all sub-delims",
			input:           "!$&'()*+,;=",
			expectedSegment: "!$&'()*+,;=",
			expectedRest:    "",
			expectError:     false,
		},
		{
			name:            "segment with brackets",
			input:           "test[bracket]",
			expectedSegment: "test",
			expectedRest:    "[bracket]",
			expectError:     false,
		},
		{
			name:            "wildcard segment",
			input:           "*",
			expectedSegment: "*",
			expectedRest:    "",
			expectError:     false,
		},
		{
			name:            "wildcard with slash",
			input:           "*/users",
			expectedSegment: "*",
			expectedRest:    "/users",
			expectError:     false,
		},
		{
			name:            "wildcard at end with slash",
			input:           "*",
			expectedSegment: "*",
			expectedRest:    "",
			expectError:     false,
		},
		{
			name:            "invalid partial wildcard",
			input:           "*abc",
			expectedSegment: "",
			expectedRest:    "",
			expectError:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			segment, rest, err := parsePathSegmentPattern(tt.input)

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

			if segment != tt.expectedSegment {
				t.Errorf("expected segment %q, got %q", tt.expectedSegment, segment)
			}

			if rest != tt.expectedRest {
				t.Errorf("expected rest %q, got %q", tt.expectedRest, rest)
			}
		})
	}
}

func TestParsePath(t *testing.T) {
	tests := []struct {
		name             string
		input            string
		expectedSegments []segmentPattern
		expectedRest     string
		expectError      bool
	}{
		{
			name:             "empty string",
			input:            "",
			expectedSegments: nil,
			expectedRest:     "",
			expectError:      false,
		},
		{
			name:             "single segment",
			input:            "/api",
			expectedSegments: []segmentPattern{"api"},
			expectedRest:     "",
			expectError:      false,
		},
		{
			name:             "multiple segments",
			input:            "/api/v1/users",
			expectedSegments: []segmentPattern{"api", "v1", "users"},
			expectedRest:     "",
			expectError:      false,
		},
		{
			name:             "relative path",
			input:            "api/users",
			expectedSegments: []segmentPattern{"api", "users"},
			expectedRest:     "",
			expectError:      false,
		},
		{
			name:             "path with trailing slash",
			input:            "/api/users/",
			expectedSegments: []segmentPattern{"api", "users"},
			expectedRest:     "",
			expectError:      false,
		},
		{
			name:             "path with query string",
			input:            "/api/users?limit=10",
			expectedSegments: []segmentPattern{"api", "users"},
			expectedRest:     "?limit=10",
			expectError:      false,
		},
		{
			name:             "path with fragment",
			input:            "/docs/api#authentication",
			expectedSegments: []segmentPattern{"docs", "api"},
			expectedRest:     "#authentication",
			expectError:      false,
		},
		{
			name:             "path with encoded segments",
			input:            "/api/hello%20world/test",
			expectedSegments: []segmentPattern{"api", "hello%20world", "test"},
			expectedRest:     "",
			expectError:      false,
		},
		{
			name:             "path with special chars",
			input:            "/api/filter='test'&sort=name/results",
			expectedSegments: []segmentPattern{"api", "filter='test'&sort=name", "results"},
			expectedRest:     "",
			expectError:      false,
		},
		{
			name:             "just slash",
			input:            "/",
			expectedSegments: nil,
			expectedRest:     "",
			expectError:      false,
		},
		{
			name:             "empty segments",
			input:            "/api//users",
			expectedSegments: []segmentPattern{"api"},
			expectedRest:     "/users",
			expectError:      false,
		},
		{
			name:             "path with port-like segment",
			input:            "/host:8080/status",
			expectedSegments: []segmentPattern{"host:8080", "status"},
			expectedRest:     "",
			expectError:      false,
		},
		{
			name:             "path stops at space",
			input:            "/api/test hello",
			expectedSegments: []segmentPattern{"api", "test"},
			expectedRest:     " hello",
			expectError:      false,
		},
		{
			name:             "path with hyphens and underscores",
			input:            "/my-api/user_data/file-name.txt",
			expectedSegments: []segmentPattern{"my-api", "user_data", "file-name.txt"},
			expectedRest:     "",
			expectError:      false,
		},
		{
			name:             "path with tildes",
			input:            "/api/~user/docs~backup",
			expectedSegments: []segmentPattern{"api", "~user", "docs~backup"},
			expectedRest:     "",
			expectError:      false,
		},
		{
			name:             "numeric segments",
			input:            "/api/v2/users/12345",
			expectedSegments: []segmentPattern{"api", "v2", "users", "12345"},
			expectedRest:     "",
			expectError:      false,
		},
		{
			name:             "single character segments",
			input:            "/a/b/c",
			expectedSegments: []segmentPattern{"a", "b", "c"},
			expectedRest:     "",
			expectError:      false,
		},
		{
			name:             "path with at symbol",
			input:            "/user@domain.com/profile",
			expectedSegments: []segmentPattern{"user@domain.com", "profile"},
			expectedRest:     "",
			expectError:      false,
		},
		{
			name:             "path with wildcard segment",
			input:            "/api/*/users",
			expectedSegments: []segmentPattern{"api", "*", "users"},
			expectedRest:     "",
			expectError:      false,
		},
		{
			name:             "path with multiple wildcards",
			input:            "/*/v1/*/profile",
			expectedSegments: []segmentPattern{"*", "v1", "*", "profile"},
			expectedRest:     "",
			expectError:      false,
		},
		{
			name:             "path ending with wildcard",
			input:            "/api/users/*",
			expectedSegments: []segmentPattern{"api", "users", "*"},
			expectedRest:     "",
			expectError:      false,
		},
		{
			name:             "path starting with wildcard",
			input:            "/*/users",
			expectedSegments: []segmentPattern{"*", "users"},
			expectedRest:     "",
			expectError:      false,
		},
		{
			name:             "path with wildcard and query",
			input:            "/api/*/users?limit=10",
			expectedSegments: []segmentPattern{"api", "*", "users"},
			expectedRest:     "?limit=10",
			expectError:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			segments, rest, err := parsePathPattern(tt.input)

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

			if len(segments) != len(tt.expectedSegments) {
				t.Errorf("expected %d segments, got %d", len(tt.expectedSegments), len(segments))
				return
			}

			for i, expectedSeg := range tt.expectedSegments {
				if segments[i] != expectedSeg {
					t.Errorf("expected segment[%d] %q, got %q", i, expectedSeg, segments[i])
				}
			}

			if rest != tt.expectedRest {
				t.Errorf("expected rest %q, got %q", tt.expectedRest, rest)
			}
		})
	}
}

func TestParseAllowRule(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		expectedRule Rule
		expectError  bool
	}{
		{
			name:  "empty string",
			input: "",
			expectedRule: Rule{
				Raw: "",
			},
			expectError: false,
		},
		{
			name:  "method only",
			input: "method=GET",
			expectedRule: Rule{
				Raw:            "method=GET",
				MethodPatterns: map[methodPattern]struct{}{methodPattern("GET"): {}},
			},
			expectError: false,
		},
		{
			name:  "domain only",
			input: "domain=google.com",
			expectedRule: Rule{
				Raw:         "domain=google.com",
				HostPattern: []labelPattern{labelPattern("com"), labelPattern("google")},
			},
			expectError: false,
		},
		{
			name:  "path only",
			input: "path=/api/v1",
			expectedRule: Rule{
				Raw:         "path=/api/v1",
				PathPattern: []segmentPattern{segmentPattern("api"), segmentPattern("v1")},
			},
			expectError: false,
		},
		{
			name:  "method and domain",
			input: "method=POST domain=api.example.com",
			expectedRule: Rule{
				Raw:            "method=POST domain=api.example.com",
				MethodPatterns: map[methodPattern]struct{}{methodPattern("POST"): {}},
				HostPattern:    []labelPattern{labelPattern("com"), labelPattern("example"), labelPattern("api")},
			},
			expectError: false,
		},
		{
			name:  "all three keys",
			input: "method=DELETE domain=test.com path=/resources/456",
			expectedRule: Rule{
				Raw:            "method=DELETE domain=test.com path=/resources/456",
				MethodPatterns: map[methodPattern]struct{}{methodPattern("DELETE"): {}},
				HostPattern:    []labelPattern{labelPattern("com"), labelPattern("test")},
				PathPattern:    []segmentPattern{segmentPattern("resources"), segmentPattern("456")},
			},
			expectError: false,
		},
		{
			name:  "wildcard domain",
			input: "domain=*.example.com",
			expectedRule: Rule{
				Raw:         "domain=*.example.com",
				HostPattern: []labelPattern{labelPattern("com"), labelPattern("example"), labelPattern("*")},
			},
			expectError: false,
		},
		{
			name:  "wildcard path",
			input: "path=/api/*/users",
			expectedRule: Rule{
				Raw:         "path=/api/*/users",
				PathPattern: []segmentPattern{segmentPattern("api"), segmentPattern("*"), segmentPattern("users")},
			},
			expectError: false,
		},
		{
			name:  "wildcard method",
			input: "method=*",
			expectedRule: Rule{
				Raw:            "method=*",
				MethodPatterns: map[methodPattern]struct{}{methodPattern("*"): {}},
			},
			expectError: false,
		},
		{
			name:  "all wildcards",
			input: "method=* domain=*.* path=/*/",
			expectedRule: Rule{
				Raw:            "method=* domain=*.* path=/*/",
				MethodPatterns: map[methodPattern]struct{}{methodPattern("*"): {}},
				HostPattern:    []labelPattern{labelPattern("*"), labelPattern("*")},
				PathPattern:    []segmentPattern{segmentPattern("*")},
			},
			expectError: false,
		},
		{
			name:         "invalid key",
			input:        "invalid=value",
			expectedRule: Rule{},
			expectError:  true,
		},
		{
			name:         "missing value",
			input:        "method=",
			expectedRule: Rule{},
			expectError:  true,
		},
		{
			name:         "invalid method",
			input:        "method=@invalid",
			expectedRule: Rule{},
			expectError:  true,
		},
		{
			name:         "invalid domain",
			input:        "domain=-invalid.com",
			expectedRule: Rule{},
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, err := parseAllowRule(tt.input)

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

			// Check Raw field
			if rule.Raw != tt.expectedRule.Raw {
				t.Errorf("expected Raw %q, got %q", tt.expectedRule.Raw, rule.Raw)
			}

			// Check MethodPatterns
			if tt.expectedRule.MethodPatterns == nil {
				if rule.MethodPatterns != nil {
					t.Errorf("expected MethodPatterns to be nil, got %v", rule.MethodPatterns)
				}
			} else {
				if rule.MethodPatterns == nil {
					t.Errorf("expected MethodPatterns %v, got nil", tt.expectedRule.MethodPatterns)
				} else {
					if len(rule.MethodPatterns) != len(tt.expectedRule.MethodPatterns) {
						t.Errorf("expected %d methods, got %d", len(tt.expectedRule.MethodPatterns), len(rule.MethodPatterns))
					}
					for method := range tt.expectedRule.MethodPatterns {
						if _, exists := rule.MethodPatterns[method]; !exists {
							t.Errorf("expected method %q not found", method)
						}
					}
				}
			}

			// Check HostPattern
			if len(rule.HostPattern) != len(tt.expectedRule.HostPattern) {
				t.Errorf("expected HostPattern length %d, got %d", len(tt.expectedRule.HostPattern), len(rule.HostPattern))
			} else {
				for i, expectedLabel := range tt.expectedRule.HostPattern {
					if rule.HostPattern[i] != expectedLabel {
						t.Errorf("expected HostPattern[%d] %q, got %q", i, expectedLabel, rule.HostPattern[i])
					}
				}
			}

			// Check PathPattern
			if len(rule.PathPattern) != len(tt.expectedRule.PathPattern) {
				t.Errorf("expected PathPattern length %d, got %d", len(tt.expectedRule.PathPattern), len(rule.PathPattern))
			} else {
				for i, expectedSegment := range tt.expectedRule.PathPattern {
					if rule.PathPattern[i] != expectedSegment {
						t.Errorf("expected PathPattern[%d] %q, got %q", i, expectedSegment, rule.PathPattern[i])
					}
				}
			}
		})
	}
}
