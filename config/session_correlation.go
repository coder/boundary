package config

import (
	"fmt"
	"net/url"
	"strings"
)

// Default header names and paths for session correlation.
const (
	DefaultSessionIDHeaderName      = "X-Coder-Agent-Firewall-Session-Id"
	DefaultSequenceNumberHeaderName = "X-Coder-Agent-Firewall-Sequence-Number"

	// DefaultAIBridgePath is the path glob used when auto-deriving an inject
	// target from CODER_AGENT_URL.
	DefaultAIBridgePath = "/api/v2/aibridge/*"

	// CoderAgentURLEnv is the environment variable set by the Coder workspace
	// agent that points to the control plane. Boundary uses it to derive a
	// default inject target when none is explicitly configured.
	CoderAgentURLEnv = "CODER_AGENT_URL"
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

// DefaultInjectTargetFromEnv derives an InjectTarget from the CODER_AGENT_URL
// variable in the provided environment slice. It returns nil if the variable is
// absent, empty, or not a valid URL with a host. The derived target uses
// DefaultAIBridgePath as the path glob so that all AI Bridge traffic on the
// control-plane host is matched.
//
// The environ parameter is accepted rather than reading os.Environ directly so
// that callers (and tests) can supply an arbitrary environment.
func DefaultInjectTargetFromEnv(environ []string) *InjectTarget {
	var raw string
	for _, e := range environ {
		k, v, ok := strings.Cut(e, "=")
		if ok && k == CoderAgentURLEnv {
			raw = v
			break
		}
	}
	if raw == "" {
		return nil
	}

	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil
	}

	return &InjectTarget{
		Domain: u.Hostname(),
		Path:   DefaultAIBridgePath,
	}
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
