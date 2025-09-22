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
		expectedHost host
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
			expectedHost: host{label("google"), label("com")},
			expectedRest: "",
			expectError:  false,
		},
		{
			name:         "subdomain",
			input:        "api.google.com",
			expectedHost: host{label("api"), label("google"), label("com")},
			expectedRest: "",
			expectError:  false,
		},
		{
			name:         "single label",
			input:        "localhost",
			expectedHost: host{label("localhost")},
			expectedRest: "",
			expectError:  false,
		},
		{
			name:         "domain with trailing content",
			input:        "example.org/path",
			expectedHost: host{label("example"), label("org")},
			expectedRest: "/path",
			expectError:  false,
		},
		{
			name:         "domain with port",
			input:        "localhost:8080",
			expectedHost: host{label("localhost")},
			expectedRest: ":8080",
			expectError:  false,
		},
		{
			name:         "numeric labels",
			input:        "192.168.1.1",
			expectedHost: host{label("192"), label("168"), label("1"), label("1")},
			expectedRest: "",
			expectError:  false,
		},
		{
			name:         "hyphenated domain",
			input:        "my-site.example-domain.co.uk",
			expectedHost: host{label("my-site"), label("example-domain"), label("co"), label("uk")},
			expectedRest: "",
			expectError:  false,
		},
		{
			name:         "alphanumeric labels",
			input:        "a1b2c3.test123.com",
			expectedHost: host{label("a1b2c3"), label("test123"), label("com")},
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
			expectedHost: host{label("test")},
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
			expectedHost: host{label("a"), label("b"), label("c")},
			expectedRest: "",
			expectError:  false,
		},
		{
			name:         "mixed case",
			input:        "Example.COM",
			expectedHost: host{label("Example"), label("COM")},
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
