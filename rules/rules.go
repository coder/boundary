package rules

import (
	"errors"
	"fmt"
	"log/slog"
	neturl "net/url"
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
	// sub paths automatically match
	PathPattern []segmentPattern

	// The labels of the host, i.e. ["google", "com"]
	// nil means all hosts allowed
	// A label of `*` acts as a wild card.
	// subdomains automatically match
	HostPattern []labelPattern

	// The allowed http methods
	// nil means all methods allowed
	MethodPatterns map[methodPattern]struct{}

	// Raw rule string for logging
	Raw string
}

type methodPattern string

// Beyond the 9 methods defined in HTTP 1.1, there actually are many more seldom used extension methods by
// various systems.
// https://datatracker.ietf.org/doc/html/rfc7230#section-3.2.6
func parseMethodPattern(token string) (methodPattern, string, error) {
	if token == "" {
		return "", "", errors.New("expected http token, got empty string")
	}
	return doParseMethodPattern(token, nil)
}

func doParseMethodPattern(token string, acc []byte) (methodPattern, string, error) {
	// BASE CASE: if the token passed in is empty, we're done parsing
	if token == "" {
		return methodPattern(acc), "", nil
	}

	// If the next byte in the string is not a valid http token character, we're done parsing.
	if !isHTTPTokenChar(token[0]) {
		return methodPattern(acc), token, nil
	}

	// The next character is valid, so the http token continues
	acc = append(acc, token[0])
	return doParseMethodPattern(token[1:], acc)
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
func parseHostPattern(input string) (host []labelPattern, rest string, err error) {
	rest = input
	var label labelPattern

	if input == "" {
		return nil, "", errors.New("expected host, got empty string")
	}

	// There should be at least one label.
	label, rest, err = parseLabelPattern(rest)
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

		label, rest, err = parseLabelPattern(rest)
		if err != nil {
			return nil, "", err
		}
		host = append(host, label)
	}

	return host, rest, nil
}

// Represents a valid label in a hostname. For example, wobble in `wib-ble.wobble.com`.
type labelPattern string

func parseLabelPattern(rest string) (labelPattern, string, error) {
	if rest == "" {
		return "", "", errors.New("expected label, got empty string")
	}

	// If the label is simply an asterisk, good to go.
	if rest[0] == '*' {
		return "*", rest[1:], nil
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

	return labelPattern(rest[:i]), rest[i:], nil
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

func parsePathPattern(input string) ([]segmentPattern, string, error) {
	if input == "" {
		return nil, "", nil
	}

	var segments []segmentPattern
	rest := input

	// If the path doesn't start with '/', it's not a valid absolute path
	// But we'll be flexible and parse relative paths too
	for {
		// Skip leading slash if present
		if rest != "" && rest[0] == '/' {
			rest = rest[1:]
		}

		// If we've consumed all input, we're done
		if rest == "" {
			break
		}

		// Parse the next segment
		seg, remaining, err := parsePathSegmentPattern(rest)
		if err != nil {
			return nil, "", err
		}

		// If we got an empty segment and there's still input,
		// it means we hit an invalid character
		if seg == "" && remaining != "" {
			break
		}

		segments = append(segments, seg)
		rest = remaining

		// If there's no slash after the segment, we're done parsing the path
		if rest == "" || rest[0] != '/' {
			break
		}
	}

	return segments, rest, nil
}

// Represents a valid url path segmentPattern.
type segmentPattern string

func parsePathSegmentPattern(input string) (segmentPattern, string, error) {
	if input == "" {
		return "", "", nil
	}

	if len(input) > 0 && input[0] == '*' {
		if len(input) > 1 && input[1] != '/' {
			return "", "", fmt.Errorf("path segment wildcards must be for the entire segment, got: %s", input)
		}

		return segmentPattern(input[0]), input[1:], nil
	}

	var i int
	for i = 0; i < len(input); i++ {
		c := input[i]

		// Check for percent-encoded characters (%XX)
		if c == '%' {
			if i+2 >= len(input) || !isHexDigit(input[i+1]) || !isHexDigit(input[i+2]) {
				break
			}
			i += 2
			continue
		}

		// Check for valid pchar characters
		if !isPChar(c) {
			break
		}
	}

	return segmentPattern(input[:i]), input[i:], nil
}

// isUnreserved returns true if the character is unreserved per RFC 3986
// unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
func isUnreserved(c byte) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

// isSubDelim returns true if the character is a sub-delimiter per RFC 3986
// sub-delims = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="
func isSubDelim(c byte) bool {
	return c == '!' || c == '$' || c == '&' || c == '\'' ||
		c == '(' || c == ')' || c == '*' || c == '+' ||
		c == ',' || c == ';' || c == '='
}

// isPChar returns true if the character is valid in a path segment (excluding percent-encoded)
// pchar = unreserved / sub-delims / ":" / "@"
func isPChar(c byte) bool {
	return isUnreserved(c) || isSubDelim(c) || c == ':' || c == '@'
}

// isHexDigit returns true if the character is a hexadecimal digit
func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') ||
		(c >= 'A' && c <= 'F') ||
		(c >= 'a' && c <= 'f')
}

// parseKey parses the predefined keys that the cli can handle. Also strips the `=` following the key.
func parseKey(rule string) (string, string, error) {
	if rule == "" {
		return "", "", errors.New("expected key")
	}

	// These are the current keys we support.
	keys := []string{"method", "domain", "path"}

	for _, key := range keys {
		if rest, found := strings.CutPrefix(rule, key+"="); found {
			return key, rest, nil
		}
	}

	return "", "", errors.New("expected key")
}

func parseAllowRule(ruleStr string) (Rule, error) {
	rule := Rule{
		Raw: ruleStr,
	}

	rest := ruleStr

	for rest != "" {
		// Parse the key
		key, valueRest, err := parseKey(rest)
		if err != nil {
			return Rule{}, fmt.Errorf("failed to parse key: %v", err)
		}

		// Parse the value based on the key type
		switch key {
		case "method":
			token, remaining, err := parseMethodPattern(valueRest)
			if err != nil {
				return Rule{}, fmt.Errorf("failed to parse method: %v", err)
			}

			// Initialize Methods map if needed
			if rule.MethodPatterns == nil {
				rule.MethodPatterns = make(map[methodPattern]struct{})
			}
			rule.MethodPatterns[token] = struct{}{}
			rest = remaining

		case "domain":
			hostLabels, remaining, err := parseHostPattern(valueRest)
			if err != nil {
				return Rule{}, fmt.Errorf("failed to parse domain: %v", err)
			}

			// Convert labels to strings in reverse order (TLD first)
			rule.HostPattern = make([]labelPattern, len(hostLabels))
			for i, label := range hostLabels {
				rule.HostPattern[len(hostLabels)-1-i] = label
			}
			rest = remaining

		case "path":
			segments, remaining, err := parsePathPattern(valueRest)
			if err != nil {
				return Rule{}, fmt.Errorf("failed to parse path: %v", err)
			}

			// Convert segments to strings
			rule.PathPattern = make([]segmentPattern, len(segments))
			copy(rule.PathPattern, segments)
			rest = remaining

		default:
			return Rule{}, fmt.Errorf("unknown key: %s", key)
		}

		// Skip whitespace or comma separators
		for rest != "" && (rest[0] == ' ' || rest[0] == '\t' || rest[0] == ',') {
			rest = rest[1:]
		}
	}

	return rule, nil
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

	// Check method patterns if they exist
	if r.MethodPatterns != nil {
		methodMatches := false
		for mp := range r.MethodPatterns {
			if string(mp) == method || string(mp) == "*" {
				methodMatches = true
				break
			}
		}
		if !methodMatches {
			return false
		}
	}

	parsedUrl, err := neturl.Parse(url)
	if err != nil {
		return false
	}

	if r.HostPattern != nil {
		// For a host pattern to match, every label has to match or be an `*`.
		// Subdomains also match automatically, meaning if the pattern is "wobble.com"
		// and the real is "wibble.wobble.com", it should match. We check this by comparing
		// from the end since patterns are stored in reverse order (TLD first).

		labels := strings.Split(parsedUrl.Hostname(), ".")

		// If the host pattern is longer than the actual host, it's definitely not a match
		if len(r.HostPattern) > len(labels) {
			return false
		}

		// Compare from the end of both arrays since pattern is stored in reverse order
		for i, lp := range r.HostPattern {
			labelIndex := len(labels) - 1 - i
			if string(lp) != labels[labelIndex] && lp != "*" {
				return false
			}
		}
	}

	if r.PathPattern != nil {
		segments := strings.Split(parsedUrl.Path, "/")

		// If the path pattern is longer than the actual path, definitely not a match
		if len(r.PathPattern) > len(segments) {
			return false
		}

		// Each segment in the pattern must be either as asterisk or match the actual path segment
		for i, sp := range r.PathPattern {
			if string(sp) != segments[i] && sp != "*" {
				return false
			}
		}
	}

	return true
}
