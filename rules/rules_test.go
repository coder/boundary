package rules

import (
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// Stub test file - tests removed
func TestStub(t *testing.T) {
	// This is a stub test
	//t.Skip("stub test file")

	allowStrings := []string{
		"coder.com",
		"GET,POST github.com",
	}
	rules, err := ParseAllowSpecs(allowStrings)
	require.NoError(t, err, "Failed to parse allow specs")

	require.Len(t, rules, 2, "Expected 2 rules")
	require.Equal(t, rules[0], Rule{
		Pattern: "coder.com",
		Methods: nil,
		Raw:     "allow coder.com",
	})
	require.Equal(t, rules[1], Rule{
		Pattern: "github.com",
		Methods: map[string]bool{
			"GET":  true,
			"POST": true,
		},
		Raw: "allow GET,POST github.com",
	})

	// Create a standard slog logger with the appropriate level
	logHandler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	logger := slog.New(logHandler)

	engine := NewRuleEngine(rules, logger)
	rez := engine.Evaluate("GET", "coder.com")
	require.Equal(t, true, rez.Allowed)
	require.Equal(t, rules[0].Raw, rez.Rule)

	rez = engine.Evaluate("PUT", "coder.com")
	require.Equal(t, true, rez.Allowed)
	require.Equal(t, rules[0].Raw, rez.Rule)

	rez = engine.Evaluate("GET", "github.com")
	require.Equal(t, true, rez.Allowed)
	require.Equal(t, rules[1].Raw, rez.Rule)

	rez = engine.Evaluate("PUT", "github.com")
	require.Equal(t, false, rez.Allowed)
	require.Equal(t, "", rez.Rule)

	// Subdomains
	// Subdomains are not allowed
	rez = engine.Evaluate("GET", "dev.coder.com")
	require.Equal(t, false, rez.Allowed)
	require.Equal(t, "", rez.Rule)

	// Subdomain matches
	// Subdomains are not allowed
	engine = NewRuleEngine([]Rule{}, logger)
	rule := Rule{
		Pattern: "coder.com",
		Methods: nil,
		Raw:     "allow coder.com",
	}
	matches := engine.matches(rule, "GET", "dev.coder.com")
	require.False(t, matches)

	// * syntax should be used
	rule = Rule{
		Pattern: "*coder.com",
		Methods: nil,
		Raw:     "allow coder.com",
	}
	matches = engine.matches(rule, "GET", "dev.coder.com")
	require.True(t, matches)

	rule = Rule{
		Pattern: "*coder.com",
		Methods: nil,
		Raw:     "allow coder.com",
	}
	matches = engine.matches(rule, "GET", "coder.com")
	require.True(t, matches)
}
