package rules

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// I know a generic interface seems insane, but this one is not complicated I promise.
// a `pattern[T]` is a thing that can be matched against something of type `T`.
// For example, a pattern[http.Request] can be used to check for a match against any http.Request.
//
// The interface exists to help us build patterns from collections of simpler patterns, and to
// inject specific patterns for testing.
type pattern[T any] interface {

	// Match returns whether the provided T matches the pattern.
	Matches(T) bool
}

type Request struct {
	method 
}

// A rules engine for evaluating requests. The zero value is ready to use,
// it simply has no allow rules, and will therefore block every request.
type Engine struct {
	rules []AllowRule
}

// The result of a match. 
type Result struct {
	Allowed bool 
	Rule string
}

// AddRule adds a rule to the engine. Returns an error if it couldn't successfully
// parse the rule.
func (engine *Engine) AddRule(rule string) error {
	r, err := ParseAllowRule(rule)
	if err != nil {
		return err
	}

	engine.rules = append(engine.rules, r)
	return nil
}

// Evaluate checks the http method and url against the engines rules,
// and returns true if there's a match.
// It returns an error if some aspect of the request object provided is not valid.
func (engine *Engine) Evaluate(req http.Request) (Result, error) {

	
	

	for _, rule := range engine.rules {
		if rule.Matches(data) {
			return Result{
				Allowed: true,
				Rule:    rule,
			}, nil
		}
	}

	// No matches (the zero value of result is a failed result).
	return Result{}, nil
}

// `AllowRule` represents a single --allow flag which has been successfully parsed and can be used to
// match against an `http.Request`.
type AllowRule struct {
	raw string // Mostly for debugging

	// Used to match against a specific host string
	hostMatcher pattern[host]

	// Used to match against a specific path
	pathMatcher pattern[path]

	// Used to match against a specific http method
	methodMatcher pattern[httpToken]
}

type allowRuleData struct {
	method httpToken
	host host
	path path 
}

func (rule AllowRule) String() string {
	return rule.raw
}

// Matches returns whether the allow rule matches a particular request
func (rule *AllowRule) Matches(req allowRuleData) bool {
	return rule.hostMatcher.Matches(req.host) && rule.methodMatcher.Matches(req.method) && rule.pathMatcher.Matches(req.path)
}

// Parse allow rule parses the text provided via --allow into something
// that can be used to match against an http request.
func ParseAllowRule(input string) (AllowRule, error) {
	var rule AllowRule
	var err error

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
			return AllowRule{}, err
		}

		// Based on the key, parse the appropriate pattern
		switch key {
		case "method":
			if rule.methodMatcher != nil {
				return AllowRule{}, errors.New("duplicate method pattern provided in allow rule")
			}

			var pattern pattern[httpToken]
			pattern, rest, err = parseHTTPMethodPattern(rest)
			if err != nil {
				return AllowRule{}, fmt.Errorf("could not parse method matcher pattern: %s", err)
			}

			rule.methodMatcher = pattern
		case "domain":
			if rule.hostMatcher != nil {
				return AllowRule{}, errors.New("duplicate host pattern provided in allow rule")
			}

			var pattern pattern[host]
			pattern, rest, err = parseHostPattern(rest)
			if err != nil {
				return AllowRule{}, fmt.Errorf("could not parse host pattern: %s", err)
			}

			rule.hostMatcher = pattern
		default:
			return AllowRule{}, fmt.Errorf("unsupported key: %s", key)
		}

	}

	return rule, nil
}

// Patterns ----------

// The allow string pattern for matching http methods. Luckily for us,
// a `*` is actually a valid http method. So all we have to do is parse a
// comma seprated list of valid http methods, and then treat the `*` specially
// in the Matches method.
type httpMethodPattern []httpToken

func parseHTTPMethodPattern(pattern string) (httpMethodPattern, string, error) {
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

	ms := httpMethodPattern(methods)
	return ms, rest, nil
}

func (methods httpMethodPattern) Matches(method httpToken) bool {
	for _, m := range methods {
		// We treat the `*` method specially as a match all character.
		if string(m) == "*" || m == method {
			return true
		}
	}
	return false
}

type hostPattern []labelPattern

func (hp hostPattern) Matches(host host) bool {
	// Single asterisk matches any valid host at all
	if len(hp) == 1 && string(hp[0]) == "*" {
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

// Represents a valid url path. For example, /wobble/wibble in `mysite.com/wobble/wibble`.
// https://datatracker.ietf.org/doc/html/rfc3986#section-1.1.1
type path []segment

func parsePath(input string) (path, string, error) {
	return nil, "", errors.New("unimplemented")
}

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
