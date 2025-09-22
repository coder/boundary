package rules

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
)

type Evaluator interface {
	Evaluate(method, url string) Result
}

// Rule represents an allow rule with optional HTTP method restrictions
type Rule struct {

	// The path segments of the url
	// nil means all paths allowed
	// a path segment of `*` acts as a wild card.
	Path []string

	// The labels of the host, i.e. ["google", "com"]
	// nil means no hosts allowed
	// subdomains automatically match
	Host []string

	// The allowed http methods
	// nil means all methods allowed
	Methods map[string]struct{}

	// Raw rule string for logging
	Raw string 
}

type httpToken string

// Beyond the 9 methods defined in HTTP 1.1, there actually are many more seldom used extension methods by
// various systems.
// https://datatracker.ietf.org/doc/html/rfc7230#section-3.2.6
func parseHTTPToken(token string) (httpToken, string, error) {
	if token == "" {
		return "", "", errors.New("expected http token, got empty string")
	}
	return doParseHTTPToken(token, nil)
}

func doParseHTTPToken(token string, acc []byte) (httpToken, string, error) {
	// BASE CASE: if the token passed in is empty, we're done parsing
	if token == "" {
		return httpToken(acc), "", nil
	}

	// If the next byte in the string is not a valid http token character, we're done parsing.
	if !isHTTPTokenChar(token[0]) {
		return httpToken(acc), token, nil
	}

	// The next character is valid, so the http token continues
	acc = append(acc, token[0])
	return doParseHTTPToken(token[1:], acc)
}

// The valid characters that can be in an http token (like the lexer/parser kind of token).
func isHTTPTokenChar(c byte) bool {
	switch {
	// Alpha numeric is fine.
	case c >= 'A' && c <= 'Z':
		return true
	case c >= 'a' && c <= 'z':
		return true
	case c >= '0' && c <= '9':
		return true

	// These special characters are also allowed unbelievably.
	case c == '!' || c == '#' || c == '$' || c == '%' || c == '&' ||
		c == '\'' || c == '*' || c == '+' || c == '-' || c == '.' ||
		c == '^' || c == '_' || c == '`' || c == '|' || c == '~':
		return true

	default:
		return false
	}
}

// Represents a valid host.
// https://datatracker.ietf.org/doc/html/rfc952
// https://datatracker.ietf.org/doc/html/rfc1123#page-13
type host []label

func parseHost(input string) (host host, rest string, err error) {
	rest = input
	var label label

	if input == "" {
		return nil, "", errors.New("expected host, got empty string")
	}

	// There should be at least one label.
	label, rest, err = parseLabel(rest)
	if err != nil {
		return nil, "", err
	}
	host = append(host, label)

	// A host is just a bunch of labels separated by `.` characters.
	var found bool
	for {
		rest, found = strings.CutPrefix(rest, ".")
		if !found {
			break
		}

		label, rest, err = parseLabel(rest)
		if err != nil {
			return nil, "", err
		}
		host = append(host, label)
	}

	return host, rest, nil
}

// Represents a valid label in a hostname. For example, wobble in `wib-ble.wobble.com`.
type label string

func parseLabel(rest string) (label, string, error) {
	if rest == "" {
		return "", "", errors.New("expected label, got empty string")
	}

	// First try to get a valid leading char. Leading char in a label cannot be a hyphen.
	if !isValidLabelChar(rest[0]) || rest[0] == '-' {
		return "", "", fmt.Errorf("could not pull label from front of string: %s", rest)
	}

	// Go until the next character is not a valid char
	var i int
	for i = 1; i < len(rest) && isValidLabelChar(rest[i]); i += 1 {
	}

	// Final char in a label cannot be a hyphen.
	if rest[i-1] == '-' {
		return "", "", fmt.Errorf("invalid label: %s", rest[:i])
	}

	return label(rest[:i]), rest[i:], nil
}

func isValidLabelChar(c byte) bool {
	switch {
	// Alpha numeric is fine.
	case c >= 'A' && c <= 'Z':
		return true
	case c >= 'a' && c <= 'z':
		return true
	case c >= '0' && c <= '9':
		return true

	// Hyphens are good
	case c == '-':
		return true

	default:
		return false
	}
}

func parseAllowRule(string) (Rule, error) {
	return Rule{}, nil
}

// ParseAllowSpecs parses a slice of --allow specs into allow Rules.
func ParseAllowSpecs(allowStrings []string) ([]Rule, error) {
	var out []Rule
	for _, s := range allowStrings {
		r, err := parseAllowRule(s)
		if err != nil {
			return nil, fmt.Errorf("failed to parse allow '%s': %v", s, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// Engine evaluates HTTP requests against a set of rules
type Engine struct {
	rules  []Rule
	logger *slog.Logger
}

// NewRuleEngine creates a new rule engine
func NewRuleEngine(rules []Rule, logger *slog.Logger) *Engine {
	return &Engine{
		rules:  rules,
		logger: logger,
	}
}

// Result contains the result of rule evaluation
type Result struct {
	Allowed bool
	Rule    string // The rule that matched (if any)
}

// Evaluate evaluates a request and returns both result and matching rule
func (re *Engine) Evaluate(method, url string) Result {
	// Check if any allow rule matches
	for _, rule := range re.rules {
		if re.matches(rule, method, url) {
			return Result{
				Allowed: true,
				Rule:    rule.Raw,
			}
		}
	}

	// Default deny if no allow rules match
	return Result{
		Allowed: false,
		Rule:    "",
	}
}

// Matches checks if the rule matches the given method and URL using wildcard patterns
func (re *Engine) matches(r Rule, method, url string) bool {
	// If the rule doesn't have any method filters, don't restrict the allowed methods
	if r.Methods == nil {
		return true
	}

	// If the rule has method filters and the provided method is not one of them, block the request.
	if _, methodIsAllowed := r.Methods[method]; !methodIsAllowed {
		return false
	}

	return true
}
