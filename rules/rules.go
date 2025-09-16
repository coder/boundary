package rules

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
)

type Pattern interface {

	// Match returns whether the provided string matches the pattern.
	Matches(string) bool
}

// The valid characters that can be in an http token (like the lexer/parser kind of token).
func isTokenChar(c byte) bool {
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

// Beyond the 9 methods defined in HTTP 1.1, there actually are many more seldom used extension methods by
// various systems. We have to handle any valid http token as a method, but we also want to parse it to avoid
// injection attacks (we won't run this tool with user input, but open source users may).
// https://datatracker.ietf.org/doc/html/rfc7230#section-3.2.6
type httpToken string

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
	if !isTokenChar(token[0]) {
		return httpToken(acc), token, nil
	}

	// The next character is valid, so the http token continues
	acc = append(acc, token[0])
	return doParseHTTPToken(token[1:], acc)
}

// The `*` to match any method.
type anyMethod struct{}

// Matches any valid httpToken
func (*anyMethod) Matches(method string) bool {
	_, _, err := parseHTTPToken(method)
	return err != nil
}

// HTTP methods separated by commas.
type setOfMethods []httpToken

func (methods *setOfMethods) Matches(method string) bool {
	for _, m := range *methods {

		// Direct string match. In the http spec, capitalization matters.
		if string(m) == method {
			return true
		}
	}

	return false
}

func parseHTTPMethodPattern(pattern string) (Pattern, string, error) {
	// Our syntax treats `*` as a shorthand for allowing any method, rather than a valid http token
	// (which hilariously it is, but you'd be insane to use it as a method name in your system).
	if pattern[0] == '*' {
		return &anyMethod{}, pattern[1:], nil
	}

	// Since it's not the wildcard, it's one or more http methods separated by commas
	methods := []httpToken{}

	// Expect at least one valid method
	token, rest, err := parseHTTPToken(pattern)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse http method from front of: %s", pattern)
	}
	methods = append(methods, httpToken(token))

	// followed by zero or more separated by commas
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

// Rule represents an allow rule with optional HTTP method restrictions
type Rule struct {
	raw string // for logging

	httpMethods    []Pattern // The methods the rule allows.
	domainSegments []Pattern // The pieces of the domain ending in the tld, i.e. ["*", "google", "com"] for *.google.com
	pathSegments   []Pattern // The path segments of the url, i.e. ["posts", "*"] for /posts/*
}

func (r Rule) String() string {
	return r.raw
}

// parseRule parses a Rule from the allow string.
// Example: `--allow "method=GET domain=github.com path=*"`
func ParseRule(input string) (rule Rule, err error) {

	// Start with a zeroed rule.
	r := Rule{raw: input}

	// Allow rules are made of 0 or more specific key value pairs, separated by spaces
	rest := input 
	var key string
	var pattern Pattern

	for {
		// Trim any leading/separating whitespace
		rest = strings.TrimLeft(rest, " ")
		if rest == "" {
			break
		}

		// Get the filter key
		key, rest, err = parseKey(rest)
		if err != nil {
			return Rule{}, err
		}

		switch key {
		case "method":
			pattern, rest, err = parseHTTPMethodPattern(rest)
			if err != nil {
				return Rule{}, err
			}

			r.httpMethods = append(r.httpMethods, pattern)
		default: 
			return Rule{}, fmt.Errorf("unsupported key: %s", key)
		}

	}

	return r, nil
}

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
