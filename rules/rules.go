package rules

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
)

// I know a private generic interface seems insane, but this one is not complicated I promise.
// a `pattern[T]` is a thing that can be matched against something of type `T`.
// For example, a pattern[httpToken] can be used as a matcher with any httpToken.
type pattern[T any] interface {

	// Match returns whether the provided T matches the pattern.
	Matches(T) bool
}

// Rule represents an allow rule.
type Rule struct {
	// A slice of patterns for matching against valid http identifiers (i.e. GET, HEAD, custom-method-1, etc.)
	httpMethods []pattern[httpToken]

	// A slice of patterns for matching against valid hosts (i.e. wibble.wobble.org)
	domainSegments []pattern[host]

	// A slice of patterns for matching against valid path segments (i.e. /wibble/wobble)
	pathSegments []pattern[segment]
}

// RuleParser is responsible for, well, parsing allow rules.
// The zero value is ready to use. Consider setting the `Strict` flag.
type RuleParser struct {

	// A lot of the valid characters in https methods, host labels, and path segments open the user to the opportunity
	// for command injection attacks when logged. If you know you're in control of the input, flexibility is probably best.
	// However, if the allow string is coming from user input (like a runtime config), consider using the strict mode
	// to limit the patterns that can be provided.
	Strict bool
}

func (rp *RuleParser) ParseRule(input string) (rule Rule, err error) {

	// We're going to mutate this "rest" variable over and over as we parse stuff from it.
	// Best not to confuse it with the original input.
	rest := input
	for {
		// Trim any leading whitespace
		rest = strings.TrimLeft(rest, " ")

		// Base Case: The allow string is finished
		if rest == "" {
			break
		}

		// Get the filter key
		var key string
		key, rest, err = parseKey(rest)
		if err != nil {
			return Rule{}, err
		}

		// Based on the key, parse the appropriate pattern
		switch key {
		case "method":
			var pattern pattern[httpToken]
			pattern, rest, err = parseHTTPMethodPattern(rest)
			if err != nil {
				return Rule{}, err
			}
			rule.httpMethods = append(rule.httpMethods, pattern)
		case "domain":
			var pattern pattern[host]
			pattern, rest, err = parseHostPattern(rest)
			if err != nil {
				return Rule{}, err
			}
			rule.domainSegments = append(rule.domainSegments, pattern)
		default:
			return Rule{}, fmt.Errorf("unsupported key: %s", key)
		}

	}

	return rule, nil
}

func parseHTTPMethodPattern(pattern string) (pattern[httpToken], string, error) {
	methods := []httpToken{}

	// Expect at least one valid method
	token, rest, err := parseHTTPToken(pattern)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse http method from front of: %s", pattern)
	}
	methods = append(methods, httpToken(token))

	// followed by zero or more http tokens separated by commas
	for {
		// Peek the comma to see if there's more
		r, found := strings.CutPrefix(rest, ",")
		if !found {
			break
		}

		token, rest, err = parseHTTPToken(r)
		if err != nil {
			return nil, "", fmt.Errorf("failed to parse http method from front of: %s", pattern)
		}
		methods = append(methods, httpToken(token))
	}

	ms := setOfMethods(methods)
	return &ms, rest, nil
}

// Beyond the 9 methods defined in HTTP 1.1, there actually are many more seldom used extension methods by
// various systems.
// https://datatracker.ietf.org/doc/html/rfc7230#section-3.2.6
type httpToken string

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

	// First try to get a valid leading char
	if !isValidLeadingOrEndingLabelChar(rest[0]) {
		return "", "", fmt.Errorf("could not pull label from front of string: %s", rest)
	}

	// Go until the next character is not a valid char
	var i int
	for i = 0; i < len(rest) && isValidLabelChar(rest[i]); i += 1 {
	}

	// Confirm that the final character is valid
	if !isValidLeadingOrEndingLabelChar(rest[i-1]) {
		return "", "", fmt.Errorf("invalid label: %s", rest[:i])
	}

	return label(rest[:i]), rest[i:], nil
}

func isValidLeadingOrEndingLabelChar(c byte) bool {
	// segments can't start or end in hyphens
	return isValidLabelChar(c) && c != '-'
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

// Represents a valid url path. For example, /wobble/wibble in `mysite.com/wobble/wibble`.
// https://datatracker.ietf.org/doc/html/rfc3986#section-1.1.1
//
// We make some alterations for safety though.
type path []segment

// Represents a valid url path segment.
type segment string

func parsePathSegment(input string) (segment, string, error) {
	if input == "" {
		return "", "", errors.New("expected path segment, got empty string")
	}

	return segment(""), "", nil
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

// HTTP methods separated by commas.
type setOfMethods []httpToken

func (methods *setOfMethods) Matches(method httpToken) bool {
	for _, m := range *methods {
		// Technically, * is a valid httpToken. However, we use it as a shorthand for "matches everything".
		// So as long as the provided method is a valid httpToken, we're good to go. Otherwise, we look for
		// a direct match.
		if string(m) == "*" || m == method {
			return true
		}
	}

	return false
}

type hostPattern []labelPattern

func (hp *hostPattern) Matches(host host) bool {
	// Single asterisk matches any valid host at all
	if len(*hp) == 1 && string((*hp)[0]) == "*" {
		return true
	} 

	// Too sleepy to continue, will pick up tomorrow.
	return true
}

func parseHostPattern(input string) (pattern hostPattern, rest string, err error) {
	if input == "" {
		return nil, "", errors.New("expected host pattern, got empty string")
	}

	var labelPattern labelPattern

	// There should be at least one label.
	labelPattern, rest, err = parseLabelPattern(input)
	if err != nil {
		return nil, "", err
	}
	pattern = append(pattern, labelPattern)

	// A host is just a bunch of labels separated by `.` characters.
	var found bool
	for {
		rest, found = strings.CutPrefix(rest, ".")
		if !found {
			break
		}

		labelPattern, rest, err = parseLabelPattern(input)
		if err != nil {
			return nil, "", err
		}
		pattern = append(pattern, labelPattern)
	}

	return pattern, rest, nil
}

// A pattern for matching against host labels
type labelPattern string

func (lp *labelPattern) Matches(label label) bool {
	p := string(*lp)
	return p == "*" || p == string(label)
}

func parseLabelPattern(input string) (pattern labelPattern, rest string, err error) {
	if rest == "" {
		return "", "", errors.New("expected label, got empty string")
	}

	// first look to see if it's a wildcard
	if strings.HasPrefix(rest, "*.") {
		p := labelPattern("*")
		return p, strings.TrimPrefix(rest, "*"), nil
	}

	// Try to parse a valid label if it's not a wildcard
	var label label
	label, rest, err = parseLabel(rest)
	if err != nil {
		return "", "", err
	}
	p := labelPattern(label)
	return p, rest, nil
}

// parseKey parses the predefined keys that the cli can handle. Also strips the `=` following the key.
func parseKey(rule string) (string, string, error) {
	if rule == "" {
		return "", "", errors.New("expected key")
	}

	keys := []string{"method", "domain", "path"}

	for _, key := range keys {
		if rest, found := strings.CutPrefix(rule, key+"="); found {
			return key, rest, nil
		}
	}

	return "", "", errors.New("expected key")
}

// Result contains the result of rule evaluation
type Result struct {
	Allowed bool
	Rule    string // The rule that matched (if any)
}

type Evaluator interface {
	Evaluate(method, url string) Result
}

type Engine struct {
	rules  []Rule
	logger *slog.Logger
}

func NewEngine(rules []Rule, logger *slog.Logger) *Engine {
	return &Engine{
		rules:  rules,
		logger: logger,
	}
}

func (e *Engine) Evaluate(method, url string) Result {

	// For a rule to let a request through, the method, domain, and path segments
	// need to be a match
	for _, rule := range e.rules {
		// Check if one of the methods matches.
		methodMatch := false
		for _, pattern := range rule.httpMethods {
			if pattern.Matches(method) {
				methodMatch = true
				break
			}
		}

		// No method match, so we ned to try the next allow rule
		if !methodMatch {
			continue
		}

		// Everything matched, so return the rule
		return Result{
			Allowed: true,
			Rule:    rule.String(),
		}
	}

	// If we checked all the rules and none were a match, we fail.
	return Result{
		Allowed: false,
		Rule:    "",
	}
}
