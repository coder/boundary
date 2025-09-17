package rules

import (
	"fmt"
	"log/slog"
	"strings"
)

type Evaluator interface {
	Evaluate(method, url string) Result
}

// Rule represents an allow rule with optional HTTP method restrictions
type Rule struct {
	Pattern string          // wildcard pattern for matching
	Methods map[string]bool // nil means all methods allowed
	Raw     string          // rule string for logging
}

// ParseAllowSpecs parses a slice of --allow specs into allow Rules.
func ParseAllowSpecs(allowStrings []string) ([]Rule, error) {
	var out []Rule
	for _, s := range allowStrings {
		r, err := newAllowRule(s)
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
	// Check method if specified
	if r.Methods != nil && !r.Methods[strings.ToUpper(method)] {
		return false
	}

	// Check URL pattern using wildcard matching
	// Try exact match first
	if wildcardMatch(r.Pattern, url) {
		return true
	}

	// If pattern doesn't start with protocol, try matching against the URL without protocol
	if !strings.HasPrefix(r.Pattern, "http://") && !strings.HasPrefix(r.Pattern, "https://") {
		// Extract domain and path from URL
		urlWithoutProtocol := url
		if strings.HasPrefix(url, "https://") {
			urlWithoutProtocol = url[8:] // Remove "https://"
		} else if strings.HasPrefix(url, "http://") {
			urlWithoutProtocol = url[7:] // Remove "http://"
		}

		// Try matching against URL without protocol
		if wildcardMatch(r.Pattern, urlWithoutProtocol) {
			return true
		}

		// Also try matching just the domain part
		domainEnd := strings.Index(urlWithoutProtocol, "/")
		if domainEnd > 0 {
			domain := urlWithoutProtocol[:domainEnd]
			if wildcardMatch(r.Pattern, domain) {
				return true
			}
		} else {
			// No path, just domain
			if wildcardMatch(r.Pattern, urlWithoutProtocol) {
				return true
			}
		}
	}

	return false
}

// wildcardMatch performs wildcard pattern matching
// Supports * (matches any sequence of characters)
func wildcardMatch(pattern, text string) bool {
	pattern = strings.ToLower(pattern)
	text = strings.ToLower(text)

	// Handle simple case
	if pattern == "*" {
		return true
	}

	// Split pattern by '*' and check each part exists in order
	parts := strings.Split(pattern, "*")

	// If no wildcards, must be exact match
	if len(parts) == 1 {
		return pattern == text
	}

	textPos := 0
	for i, part := range parts {
		if part == "" {
			continue // Skip empty parts from consecutive '*'
		}

		if i == 0 {
			// First part must be at the beginning
			if !strings.HasPrefix(text, part) {
				return false
			}
			textPos = len(part)
		} else if i == len(parts)-1 {
			// Last part must be at the end
			if !strings.HasSuffix(text[textPos:], part) {
				return false
			}
		} else {
			// Middle parts must exist in order
			idx := strings.Index(text[textPos:], part)
			if idx == -1 {
				return false
			}
			textPos += idx + len(part)
		}
	}

	return true
}

// newAllowRule creates an allow Rule from a spec string used by --allow.
// Supported formats:
//
//	"pattern"                    -> allow all methods to pattern
//	"GET,HEAD pattern"           -> allow only listed methods to pattern
func newAllowRule(spec string) (Rule, error) {
	s := strings.TrimSpace(spec)
	if s == "" {
		return Rule{}, fmt.Errorf("invalid allow spec: empty")
	}

	var methods map[string]bool
	pattern := s

	// Detect optional leading methods list separated by commas and a space before pattern
	// e.g., "GET,HEAD github.com"
	if idx := strings.IndexFunc(s, func(r rune) bool { return r == ' ' || r == '\t' }); idx > 0 {
		left := strings.TrimSpace(s[:idx])
		right := strings.TrimSpace(s[idx:])
		// methods part is valid if it only contains letters and commas
		valid := left != "" && strings.IndexFunc(left, func(r rune) bool {
			return r != ',' && (r < 'A' || r > 'Z') && (r < 'a' || r > 'z')
		}) == -1
		if valid {
			methods = make(map[string]bool)
			for _, m := range strings.Split(left, ",") {
				m = strings.TrimSpace(m)
				if m == "" {
					continue
				}
				methods[strings.ToUpper(m)] = true
			}
			pattern = right
		}
	}

	if pattern == "" {
		return Rule{}, fmt.Errorf("invalid allow spec: missing pattern")
	}

	return Rule{
		Pattern: pattern,
		Methods: methods,
		Raw:     "allow " + spec,
	}, nil
}
