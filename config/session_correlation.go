package config

import (
	"fmt"
	"strings"
)

// Default header names for session correlation.
const (
	DefaultSessionIDHeaderName      = "X-Coder-Agent-Firewall-Session-Id"
	DefaultSequenceNumberHeaderName = "X-Coder-Agent-Firewall-Sequence-Number"
)

// InjectTarget represents a parsed target for session correlation header
// injection. Requests matching the domain (and optional path glob) will
// receive the session ID and sequence number headers.
type InjectTarget struct {
	Domain string
	Path   string
}

// SessionCorrelationConfig holds configuration for session correlation
// header injection. When enabled, boundary injects its session ID and
// sequence number as custom headers on matching outbound requests so
// that an upstream AI Bridge can correlate the request back to the
// boundary audit event stream.
type SessionCorrelationConfig struct {
	// Enabled controls whether session correlation headers are injected.
	// Deployments without AI Bridge in front should set this to false.
	Enabled bool

	// InjectTargets is the list of domain/path patterns that should
	// receive session correlation headers.
	InjectTargets []InjectTarget

	// SessionIDHeaderName is the HTTP header name used to carry the
	// boundary session ID. Defaults to DefaultSessionIDHeaderName.
	SessionIDHeaderName string

	// SequenceNumberHeaderName is the HTTP header name used to carry
	// the boundary sequence number. Defaults to
	// DefaultSequenceNumberHeaderName.
	SequenceNumberHeaderName string
}

// ParseInjectTarget parses a string of the form "domain=... path=..."
// into an InjectTarget. The domain key is required; path is optional.
func ParseInjectTarget(raw string) (InjectTarget, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return InjectTarget{}, fmt.Errorf("inject target must not be empty")
	}

	var target InjectTarget
	for _, part := range strings.Fields(raw) {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			return InjectTarget{}, fmt.Errorf(
				"inject target: malformed key-value pair %q, expected key=value", part,
			)
		}
		switch key {
		case "domain":
			if value == "" {
				return InjectTarget{}, fmt.Errorf("inject target: domain must not be empty")
			}
			target.Domain = value
		case "path":
			target.Path = value
		default:
			return InjectTarget{}, fmt.Errorf("inject target: unknown key %q", key)
		}
	}

	if target.Domain == "" {
		return InjectTarget{}, fmt.Errorf("inject target: domain is required")
	}

	return target, nil
}

// ValidateSessionCorrelation checks that the session correlation config
// is internally consistent. It returns an error describing the first
// problem found, or nil if the config is valid.
func ValidateSessionCorrelation(cfg SessionCorrelationConfig) error {
	if !cfg.Enabled {
		return nil
	}

	if len(cfg.InjectTargets) == 0 {
		return fmt.Errorf(
			"session correlation is enabled but no inject targets are configured",
		)
	}

	if cfg.SessionIDHeaderName == "" {
		return fmt.Errorf("session-id-header-name must not be empty when session correlation is enabled")
	}

	if cfg.SequenceNumberHeaderName == "" {
		return fmt.Errorf("sequence-number-header-name must not be empty when session correlation is enabled")
	}

	return nil
}
