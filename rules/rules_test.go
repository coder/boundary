package rules

import "testing"

func TestParseHTTPToken(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		expectedToken  httpToken
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
			token, remain, err := parseHTTPToken(tt.input)

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
		expectedHost []label
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
			expectedHost: []label{label("google"), label("com")},
			expectedRest: "",
			expectError:  false,
		},
		{
			name:         "subdomain",
			input:        "api.google.com",
			expectedHost: []label{label("api"), label("google"), label("com")},
			expectedRest: "",
			expectError:  false,
		},
		{
			name:         "single label",
			input:        "localhost",
			expectedHost: []label{label("localhost")},
			expectedRest: "",
			expectError:  false,
		},
		{
			name:         "domain with trailing content",
			input:        "example.org/path",
			expectedHost: []label{label("example"), label("org")},
			expectedRest: "/path",
			expectError:  false,
		},
		{
			name:         "domain with port",
			input:        "localhost:8080",
			expectedHost: []label{label("localhost")},
			expectedRest: ":8080",
			expectError:  false,
		},
		{
			name:         "numeric labels",
			input:        "192.168.1.1",
			expectedHost: []label{label("192"), label("168"), label("1"), label("1")},
			expectedRest: "",
			expectError:  false,
		},
		{
			name:         "hyphenated domain",
			input:        "my-site.example-domain.co.uk",
			expectedHost: []label{label("my-site"), label("example-domain"), label("co"), label("uk")},
			expectedRest: "",
			expectError:  false,
		},
		{
			name:         "alphanumeric labels",
			input:        "a1b2c3.test123.com",
			expectedHost: []label{label("a1b2c3"), label("test123"), label("com")},
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
			expectedHost: []label{label("test")},
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
			expectedHost: []label{label("a"), label("b"), label("c")},
			expectedRest: "",
			expectError:  false,
		},
		{
			name:         "mixed case",
			input:        "Example.COM",
			expectedHost: []label{label("Example"), label("COM")},
			expectedRest: "",
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hostResult, rest, err := parseHost(tt.input)

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
		expectedLabel label
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			labelResult, rest, err := parseLabel(tt.input)

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
		expectedSegment segment
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			segment, rest, err := parsePathSegment(tt.input)

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
		expectedSegments []segment
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
			expectedSegments: []segment{"api"},
			expectedRest:     "",
			expectError:      false,
		},
		{
			name:             "multiple segments",
			input:            "/api/v1/users",
			expectedSegments: []segment{"api", "v1", "users"},
			expectedRest:     "",
			expectError:      false,
		},
		{
			name:             "relative path",
			input:            "api/users",
			expectedSegments: []segment{"api", "users"},
			expectedRest:     "",
			expectError:      false,
		},
		{
			name:             "path with trailing slash",
			input:            "/api/users/",
			expectedSegments: []segment{"api", "users"},
			expectedRest:     "",
			expectError:      false,
		},
		{
			name:             "path with query string",
			input:            "/api/users?limit=10",
			expectedSegments: []segment{"api", "users"},
			expectedRest:     "?limit=10",
			expectError:      false,
		},
		{
			name:             "path with fragment",
			input:            "/docs/api#authentication",
			expectedSegments: []segment{"docs", "api"},
			expectedRest:     "#authentication",
			expectError:      false,
		},
		{
			name:             "path with encoded segments",
			input:            "/api/hello%20world/test",
			expectedSegments: []segment{"api", "hello%20world", "test"},
			expectedRest:     "",
			expectError:      false,
		},
		{
			name:             "path with special chars",
			input:            "/api/filter='test'&sort=name/results",
			expectedSegments: []segment{"api", "filter='test'&sort=name", "results"},
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
			expectedSegments: []segment{"api"},
			expectedRest:     "/users",
			expectError:      false,
		},
		{
			name:             "path with port-like segment",
			input:            "/host:8080/status",
			expectedSegments: []segment{"host:8080", "status"},
			expectedRest:     "",
			expectError:      false,
		},
		{
			name:             "path stops at space",
			input:            "/api/test hello",
			expectedSegments: []segment{"api", "test"},
			expectedRest:     " hello",
			expectError:      false,
		},
		{
			name:             "path with hyphens and underscores",
			input:            "/my-api/user_data/file-name.txt",
			expectedSegments: []segment{"my-api", "user_data", "file-name.txt"},
			expectedRest:     "",
			expectError:      false,
		},
		{
			name:             "path with tildes",
			input:            "/api/~user/docs~backup",
			expectedSegments: []segment{"api", "~user", "docs~backup"},
			expectedRest:     "",
			expectError:      false,
		},
		{
			name:             "numeric segments",
			input:            "/api/v2/users/12345",
			expectedSegments: []segment{"api", "v2", "users", "12345"},
			expectedRest:     "",
			expectError:      false,
		},
		{
			name:             "single character segments",
			input:            "/a/b/c",
			expectedSegments: []segment{"a", "b", "c"},
			expectedRest:     "",
			expectError:      false,
		},
		{
			name:             "path with at symbol",
			input:            "/user@domain.com/profile",
			expectedSegments: []segment{"user@domain.com", "profile"},
			expectedRest:     "",
			expectError:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			segments, rest, err := parsePath(tt.input)

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
