package rulesengine

import (
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRoundTrip(t *testing.T) {
	tcs := []struct {
		name        string
		rules       []string
		url         string
		method      string
		expectParse bool
		expectMatch bool
	}{
		{
			name:        "basic all three",
			rules:       []string{"method=GET,HEAD domain=github.com path=/wibble/wobble"},
			url:         "https://github.com/wibble/wobble",
			method:      "GET",
			expectParse: true,
			expectMatch: true,
		},
		{
			name:        "method rejects properly",
			rules:       []string{"method=GET"},
			url:         "https://github.com/wibble/wobble",
			method:      "POST",
			expectParse: true,
			expectMatch: false,
		},
		{
			name:        "domain rejects properly",
			rules:       []string{"domain=github.com"},
			url:         "https://example.com/wibble/wobble",
			method:      "GET",
			expectParse: true,
			expectMatch: false,
		},
		{
			name:        "path rejects properly",
			rules:       []string{"path=/wibble/wobble"},
			url:         "https://github.com/different/path",
			method:      "GET",
			expectParse: true,
			expectMatch: false,
		},
		{
			name:        "multiple rules - one matches",
			rules:       []string{"domain=github.com", "domain=example.com"},
			url:         "https://github.com/wibble/wobble",
			method:      "GET",
			expectParse: true,
			expectMatch: true,
		},
		{
			name:        "method wildcard matches anything",
			rules:       []string{"method=*"},
			url:         "https://github.com/wibble/wobble",
			method:      "POST",
			expectParse: true,
			expectMatch: true,
		},
		{
			name:        "domain wildcard matches anything",
			rules:       []string{"domain=*"},
			url:         "https://example.com/wibble/wobble",
			method:      "GET",
			expectParse: true,
			expectMatch: true,
		},
		{
			name:        "path wildcard matches anything",
			rules:       []string{"path=*"},
			url:         "https://github.com/any/path/here",
			method:      "GET",
			expectParse: true,
			expectMatch: true,
		},
		{
			name:        "all three wildcards match anything",
			rules:       []string{"method=* domain=* path=*"},
			url:         "https://example.com/some/random/path",
			method:      "DELETE",
			expectParse: true,
			expectMatch: true,
		},
		{
			name:        "query parameters don't break matching",
			rules:       []string{"domain=github.com path=/wibble/wobble"},
			url:         "https://github.com/wibble/wobble?param1=value1&param2=value2",
			method:      "GET",
			expectParse: true,
			expectMatch: true,
		},
		{
			name:        "domain wildcard segment matches",
			rules:       []string{"domain=*.github.com"},
			url:         "https://api.github.com/repos",
			method:      "GET",
			expectParse: true,
			expectMatch: true,
		},
		{
			name:        "domain cannot end with asterisk",
			rules:       []string{"domain=github.*"},
			url:         "https://github.com/repos",
			method:      "GET",
			expectParse: false,
			expectMatch: false,
		},
		{
			name:        "domain asterisk in middle matches",
			rules:       []string{"domain=github.*.com"},
			url:         "https://github.api.com/repos",
			method:      "GET",
			expectParse: true,
			expectMatch: true,
		},
	}

	logHandler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	logger := slog.New(logHandler)

	for _, tc := range tcs {
		rules, err := ParseAllowSpecs(tc.rules)
		if tc.expectParse {
			require.Nil(t, err)
			engine := NewRuleEngine(rules, logger)
			result := engine.Evaluate(tc.method, tc.url)
			require.Equal(t, tc.expectMatch, result.Allowed)
		} else {
			require.NotNil(t, err)
		}
	}
}
