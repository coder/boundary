package config

import (
	"fmt"
	"strings"

	"github.com/coder/serpent"
	"github.com/google/uuid"
	"github.com/spf13/pflag"
)

// JailType represents the type of jail to use for network isolation
type JailType string

const (
	NSJailType   JailType = "nsjail"
	LandjailType JailType = "landjail"
)

func NewJailTypeFromString(str string) (JailType, error) {
	switch str {
	case "nsjail":
		return NSJailType, nil
	case "landjail":
		return LandjailType, nil
	default:
		return NSJailType, fmt.Errorf("invalid JailType: %s", str)
	}
}

// AllowStringsArray is a custom type that implements pflag.Value to support
// repeatable --allow flags without splitting on commas. This allows comma-separated
// paths within a single allow rule (e.g., "path=/todos/1,/todos/2").
type AllowStringsArray []string

var _ pflag.Value = (*AllowStringsArray)(nil)

// Set implements pflag.Value. It appends the value to the slice without splitting on commas.
func (a *AllowStringsArray) Set(value string) error {
	*a = append(*a, value)
	return nil
}

// String implements pflag.Value.
func (a AllowStringsArray) String() string {
	return strings.Join(a, ",")
}

// Type implements pflag.Value.
func (a AllowStringsArray) Type() string {
	return "string"
}

// Value returns the underlying slice of strings.
func (a AllowStringsArray) Value() []string {
	return []string(a)
}

type CliConfig struct {
	Config             serpent.YAMLConfigPath `yaml:"-"`
	AllowListStrings   serpent.StringArray    `yaml:"allowlist"` // From config file
	AllowStrings       AllowStringsArray      `yaml:"-"`         // From CLI flags only
	LogLevel           serpent.String         `yaml:"log_level"`
	LogDir             serpent.String         `yaml:"log_dir"`
	ProxyPort          serpent.Int64          `yaml:"proxy_port"`
	PprofEnabled       serpent.Bool           `yaml:"pprof_enabled"`
	PprofPort          serpent.Int64          `yaml:"pprof_port"`
	JailType           serpent.String         `yaml:"jail_type"`
	UseRealDNS         serpent.Bool           `yaml:"use_real_dns"`
	NoUserNamespace    serpent.Bool           `yaml:"no_user_namespace"`
	DisableAuditLogs   serpent.Bool           `yaml:"disable_audit_logs"`
	LogProxySocketPath serpent.String         `yaml:"log_proxy_socket_path"`

	// Session correlation header injection.
	SessionCorrelationEnabled serpent.Bool           `yaml:"session_correlation_enabled"`
	InjectSessionIDOn         AllowStringsArray      `yaml:"inject_session_id_on"`
	InjectSessionIDOnYAML     serpent.StringArray     `yaml:"session_id_inject_targets"`
	SessionIDHeaderName       serpent.String          `yaml:"session_id_header_name"`
	SequenceNumberHeaderName  serpent.String          `yaml:"sequence_number_header_name"`
}

type AppConfig struct {
	AllowRules         []string
	LogLevel           string
	LogDir             string
	ProxyPort          int64
	PprofEnabled       bool
	PprofPort          int64
	JailType           JailType
	UseRealDNS         bool
	NoUserNamespace    bool
	TargetCMD          []string
	UserInfo           *UserInfo
	DisableAuditLogs   bool
	LogProxySocketPath string

	// SessionCorrelation controls header injection for AI Bridge
	// correlation. See SessionCorrelationConfig for details.
	SessionCorrelation SessionCorrelationConfig

	// SessionID is a UUIDv4 generated at process startup. It groups
	// all audit events produced by this boundary invocation into a
	// single session. Set by Run, not by configuration.
	SessionID uuid.UUID
}

func NewAppConfigFromCliConfig(cfg CliConfig, targetCMD []string) (AppConfig, error) {
	// Merge allowlist from config file with allow from CLI flags
	allowListStrings := cfg.AllowListStrings.Value()
	allowStrings := cfg.AllowStrings.Value()

	// Combine allowlist (config file) with allow (CLI flags)
	allAllowStrings := append(allowListStrings, allowStrings...)

	jailType, err := NewJailTypeFromString(cfg.JailType.Value())
	if err != nil {
		return AppConfig{}, err
	}

	userInfo := GetUserInfo()

	// Build session correlation config from CLI and YAML sources.
	sc, err := buildSessionCorrelation(cfg)
	if err != nil {
		return AppConfig{}, fmt.Errorf("session correlation config: %w", err)
	}

	return AppConfig{
		AllowRules:         allAllowStrings,
		LogLevel:           cfg.LogLevel.Value(),
		LogDir:             cfg.LogDir.Value(),
		ProxyPort:          cfg.ProxyPort.Value(),
		PprofEnabled:       cfg.PprofEnabled.Value(),
		PprofPort:          cfg.PprofPort.Value(),
		JailType:           jailType,
		UseRealDNS:         cfg.UseRealDNS.Value(),
		NoUserNamespace:    cfg.NoUserNamespace.Value(),
		TargetCMD:          targetCMD,
		UserInfo:           userInfo,
		DisableAuditLogs:   cfg.DisableAuditLogs.Value(),
		LogProxySocketPath: cfg.LogProxySocketPath.Value(),
		SessionCorrelation: sc,
	}, nil
}

// buildSessionCorrelation merges CLI and YAML inject target sources,
// parses each target string, applies header name defaults, and
// validates the resulting configuration.
func buildSessionCorrelation(cfg CliConfig) (SessionCorrelationConfig, error) {
	// Merge YAML targets with CLI targets.
	rawTargets := append(cfg.InjectSessionIDOnYAML.Value(), cfg.InjectSessionIDOn.Value()...)

	var targets []InjectTarget
	for _, raw := range rawTargets {
		t, err := ParseInjectTarget(raw)
		if err != nil {
			return SessionCorrelationConfig{}, err
		}
		targets = append(targets, t)
	}

	// Apply defaults for header names.
	sessionIDHeader := cfg.SessionIDHeaderName.Value()
	if sessionIDHeader == "" {
		sessionIDHeader = DefaultSessionIDHeaderName
	}
	seqHeader := cfg.SequenceNumberHeaderName.Value()
	if seqHeader == "" {
		seqHeader = DefaultSequenceNumberHeaderName
	}

	sc := SessionCorrelationConfig{
		Enabled:                  cfg.SessionCorrelationEnabled.Value(),
		InjectTargets:            targets,
		SessionIDHeaderName:      sessionIDHeader,
		SequenceNumberHeaderName: seqHeader,
	}

	if err := ValidateSessionCorrelation(sc); err != nil {
		return SessionCorrelationConfig{}, err
	}

	return sc, nil
}
