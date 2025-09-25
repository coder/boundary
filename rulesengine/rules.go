package rulesengine

import (
	"errors"
	"fmt"
	"strings"
)

// Rule represents an allow rule passed to the cli with --allow or read from the config file.
// Rules have a specific grammar that we need to parse carefully.
// Example: --allow="method=GET,PATCH domain=wibble.wobble.com, path=/posts/*"
type Rule struct {

	// The path segments of the url.
	// - nil means all paths allowed
	// - a path segment of `*` acts as a wild card.
	// - sub paths automatically match
	PathPattern []segmentPattern

	// The labels of the host, i.e. ["google", "com"].
	// - nil means all hosts allowed
	// - A label of `*` acts as a wild card.
	// - subdomains automatically match
	HostPattern []labelPattern

	// The allowed http methods.
	// - nil means all methods allowed
	MethodPatterns map[methodPattern]struct{}

	// Raw rule string for logging
	Raw string
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

// parseAllowRule takes an allow rule string and tries to parse it as a rule.
func parseAllowRule(ruleStr string) (Rule, error) {
	rule := Rule{
		Raw: ruleStr,
	}

	// Functions called by this function used a really common pattern: recursive descent parsing.
	// All the helper functions for parsing an allow rule will be called like `thing, rest, err := parseThing(rest)`.
	// What's going on here is that we try to parse some expected text from the front of the string.
	// If we succeed, we get back the thing we parsed and the remaining text. If we fail, we get back a non nil error.
	rest := ruleStr
	var key string
	var err error

	// Ann allow rule can have as many key=value pairs as needed, we go until there's no more text in the rule.
	for rest != "" {
		// Parse the key
		key, rest, err = parseKey(rest)
		if err != nil {
			return Rule{}, fmt.Errorf("failed to parse key: %v", err)
		}

		// Parse the value based on the key type
		switch key {
		case "method":
			// Initialize Methods map if needed
			if rule.MethodPatterns == nil {
				rule.MethodPatterns = make(map[methodPattern]struct{})
			}

			var method methodPattern
			for {
				method, rest, err = parseMethodPattern(rest)
				if err != nil {
					return Rule{}, fmt.Errorf("failed to parse method: %v", err)
				}

				rule.MethodPatterns[method] = struct{}{}

				// Check if there's a comma for more methods
				if rest != "" && rest[0] == ',' {
					rest = rest[1:] // Skip the comma
					continue
				}

				break
			}

		case "domain":
			var host []labelPattern
			host, rest, err = parseHostPattern(rest)
			if err != nil {
				return Rule{}, fmt.Errorf("failed to parse domain: %v", err)
			}

			// Convert labels to strings
			rule.HostPattern = append(rule.HostPattern, host...)

		case "path":
			var segments []segmentPattern
			segments, rest, err = parsePathPattern(rest)
			if err != nil {
				return Rule{}, fmt.Errorf("failed to parse path: %v", err)
			}

			// Convert segments to strings
			rule.PathPattern = append(rule.PathPattern, segments...)

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
func parseHostPattern(input string) ([]labelPattern, string, error) {
	rest := input
	var host []labelPattern
	var err error

	if input == "" {
		return nil, "", errors.New("expected host, got empty string")
	}

	// There should be at least one label.
	var label labelPattern
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

	// Validate: host patterns cannot end with asterisk
	if len(host) > 0 && host[len(host)-1] == "*" {
		return nil, "", errors.New("host patterns cannot end with asterisk")
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

	rest := input
	var segments []segmentPattern
	var err error

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
		var segment segmentPattern
		segment, rest, err = parsePathSegmentPattern(rest)
		if err != nil {
			return nil, "", err
		}

		// If we got an empty segment and there's still input,
		// it means we hit an invalid character
		if segment == "" && rest != "" {
			break
		}

		segments = append(segments, segment)

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
