package config

import (
	"fmt"
	"strings"

	"github.com/coder/serpent"
	"github.com/google/uuid"
	"github.com/spf13/pflag"
)

// DefaultSessionIDHeader is the HTTP header injected by boundary on every
// outgoing forwarded request.
const DefaultSessionIDHeader = "X-Coder-Agent-Firewall-Session-Id"

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
	Config                    serpent.YAMLConfigPath `yaml:"-"`
	AllowListStrings          serpent.StringArray    `yaml:"allowlist"`          // From config file
	AllowStrings              AllowStringsArray      `yaml:"-"`                  // From CLI flags only
	LogLevel                  serpent.String         `yaml:"log_level"`
	LogDir                    serpent.String         `yaml:"log_dir"`
	ProxyPort                 serpent.Int64          `yaml:"proxy_port"`
	PprofEnabled              serpent.Bool           `yaml:"pprof_enabled"`
	PprofPort                 serpent.Int64          `yaml:"pprof_port"`
	JailType                  serpent.String         `yaml:"jail_type"`
	UseRealDNS                serpent.Bool           `yaml:"use_real_dns"`
	NoUserNamespace           serpent.Bool           `yaml:"no_user_namespace"`
	DisableAuditLogs          serpent.Bool           `yaml:"disable_audit_logs"`
	LogProxySocketPath        serpent.String         `yaml:"log_proxy_socket_path"`
	SessionID                 serpent.String         `yaml:"-"`                  // CLI only; generated if empty
	SessionIDHeader           serpent.String         `yaml:"session_id_header"`
	DisableSessionIDHeader    serpent.Bool           `yaml:"disable_session_id_header"`
	SessionIDMatchList        serpent.StringArray    `yaml:"session_id_inject_domains"` // From config file
	SessionIDMatch            AllowStringsArray      `yaml:"-"`                  // From CLI flags only
}

type AppConfig struct {
	AllowRules              []string
	LogLevel                string
	LogDir                  string
	ProxyPort               int64
	PprofEnabled            bool
	PprofPort               int64
	JailType                JailType
	UseRealDNS              bool
	NoUserNamespace         bool
	TargetCMD               []string
	UserInfo                *UserInfo
	DisableAuditLogs        bool
	LogProxySocketPath      string
	// SessionID is a UUID generated at startup that identifies this boundary
	// invocation. It is injected as a header on matching outgoing HTTP requests
	// and included in audit batches sent to the workspace agent.
	SessionID               string
	// SessionIDHeader is the HTTP header name used to carry the session ID.
	// An empty value means the header is disabled.
	SessionIDHeader         string
	// SessionIDMatchRules is the merged list of match-rule strings from the
	// YAML session_id_matches key and the --session-id-match CLI flag. The
	// session ID header is only injected on requests that match at least one
	// rule. Empty means never inject.
	SessionIDMatchRules     []string
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

	sessionID := cfg.SessionID.Value()
	if sessionID == "" {
		sessionID = uuid.NewString()
	}

	sessionIDHeader := ""
	if !cfg.DisableSessionIDHeader.Value() {
		sessionIDHeader = cfg.SessionIDHeader.Value()
		if sessionIDHeader == "" {
			sessionIDHeader = DefaultSessionIDHeader
		}
	}

	// Merge session-ID match rules: YAML list first, then CLI flags (same
	// pattern as allAllowStrings above).
	allMatchStrings := append(cfg.SessionIDMatchList.Value(), cfg.SessionIDMatch.Value()...)

	return AppConfig{
		AllowRules:          allAllowStrings,
		LogLevel:            cfg.LogLevel.Value(),
		LogDir:              cfg.LogDir.Value(),
		ProxyPort:           cfg.ProxyPort.Value(),
		PprofEnabled:        cfg.PprofEnabled.Value(),
		PprofPort:           cfg.PprofPort.Value(),
		JailType:            jailType,
		UseRealDNS:          cfg.UseRealDNS.Value(),
		NoUserNamespace:     cfg.NoUserNamespace.Value(),
		TargetCMD:           targetCMD,
		UserInfo:            userInfo,
		DisableAuditLogs:    cfg.DisableAuditLogs.Value(),
		LogProxySocketPath:  cfg.LogProxySocketPath.Value(),
		SessionID:           sessionID,
		SessionIDHeader:     sessionIDHeader,
		SessionIDMatchRules: allMatchStrings,
	}, nil
}
