package rules

import (
	"fmt"
	"log/slog"
	"strings"
)

// Action represents whether to allow or deny a request
type Action int

const (
	Allow Action = iota
	Deny
)

func (a Action) String() string {
	switch a {
	case Allow:
		return "ALLOW"
	case Deny:
		return "DENY"
	default:
		return "UNKNOWN"
	}
}

// Rule represents a filtering rule with optional HTTP method restrictions
type Rule struct {
	Action  Action
	Pattern string              // wildcard pattern for matching
	Methods map[string]bool     // nil means all methods allowed
	Raw     string              // rule string for logging
}

// newRule creates a new rule from a string format like "allow: github.com" or "deny-post: telemetry.*"
func newRule(ruleStr string) (*Rule, error) {
	parts := strings.SplitN(ruleStr, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid rule format: %s (expected 'action[-method]: pattern')", ruleStr)
	}

	actionPart := strings.TrimSpace(parts[0])
	pattern := strings.TrimSpace(parts[1])

	// Parse action and optional method
	var action Action
	var methods map[string]bool

	actionParts := strings.Split(actionPart, "-")
	switch strings.ToLower(actionParts[0]) {
	case "allow":
		action = Allow
	case "deny":
		action = Deny
	default:
		return nil, fmt.Errorf("invalid action: %s (must be 'allow' or 'deny')", actionParts[0])
	}

	// Parse optional method restriction
	if len(actionParts) > 1 {
		methods = make(map[string]bool)
		for _, method := range actionParts[1:] {
			methods[strings.ToUpper(method)] = true
		}
	}

	return &Rule{
		Action:  action,
		Pattern: pattern,
		Methods: methods,
		Raw:     ruleStr,
	}, nil
}

// Matches checks if the rule matches the given method and URL using wildcard patterns
func (r *Rule) Matches(method, url string) bool {
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
	return wildcardMatchRecursive(pattern, text, 0, 0)
}

// wildcardMatchRecursive is the recursive implementation of wildcard matching
func wildcardMatchRecursive(pattern, text string, p, t int) bool {
	// If we've reached the end of the pattern
	if p == len(pattern) {
		return t == len(text) // Match if we've also reached the end of text
	}

	// If we've reached the end of text but not pattern
	if t == len(text) {
		// Only match if remaining pattern is all '*'
		for i := p; i < len(pattern); i++ {
			if pattern[i] != '*' {
				return false
			}
		}
		return true
	}

	// Handle current character in pattern
	switch pattern[p] {
	case '*':
		// '*' matches zero or more characters
		// Try matching zero characters (skip the '*')
		if wildcardMatchRecursive(pattern, text, p+1, t) {
			return true
		}
		// Try matching one or more characters
		return wildcardMatchRecursive(pattern, text, p, t+1)

	default:
		// Regular character must match exactly (case-insensitive for domains)
		patternChar := strings.ToLower(string(pattern[p]))
		textChar := strings.ToLower(string(text[t]))
		if patternChar == textChar {
			return wildcardMatchRecursive(pattern, text, p+1, t+1)
		}
		return false
	}
}

// RuleEngine evaluates HTTP requests against a set of rules
type RuleEngine struct {
	rules   []*Rule
	logger  *slog.Logger
}

// NewRuleEngine creates a new rule engine
func NewRuleEngine(rules []*Rule, logger *slog.Logger) *RuleEngine {
	return &RuleEngine{
		rules:   rules,
		logger:  logger,
	}
}

// Evaluate evaluates a request against all rules and returns the action to take
func (re *RuleEngine) Evaluate(method, url string) Action {
	// Evaluate rules in order
	for _, rule := range re.rules {
		if rule.Matches(method, url) {
			switch rule.Action {
			case Allow:
				re.logger.Info("ALLOW", "method", method, "url", url, "rule", rule.Raw)
				return Allow
			case Deny:
				re.logger.Warn("DENY", "method", method, "url", url, "rule", rule.Raw)
				return Deny
			}
		}
	}

	// Default deny if no rules match
	re.logger.Warn("DENY", "method", method, "url", url, "reason", "no matching rules")
	return Deny
}

// newAllowRule creates an allow Rule from a spec string used by --allow.
// Supported formats:
//   "pattern"                    -> allow all methods to pattern
//   "GET,HEAD pattern"           -> allow only listed methods to pattern
func newAllowRule(spec string) (*Rule, error) {
	s := strings.TrimSpace(spec)
	if s == "" {
		return nil, fmt.Errorf("invalid allow spec: empty")
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
			return !(r == ',' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z'))
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
		return nil, fmt.Errorf("invalid allow spec: missing pattern")
	}

	return &Rule{
		Action:  Allow,
		Pattern: pattern,
		Methods: methods,
		Raw:     "allow " + spec,
	}, nil
}

// ParseAllowSpecs parses a slice of --allow specs into allow Rules.
func ParseAllowSpecs(allowStrings []string) ([]*Rule, error) {
	var out []*Rule
	for _, s := range allowStrings {
		r, err := newAllowRule(s)
		if err != nil {
			return nil, fmt.Errorf("failed to parse allow '%s': %v", s, err)
		}
		out = append(out, r)
	}
	return out, nil
}