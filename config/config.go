package config

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
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

	// UpstreamProxyEnv configures Boundary's parent-side forwarding transport.
	UpstreamProxyEnv = "BOUNDARY_UPSTREAM_PROXY"

	// UpstreamProxyFlag configures Boundary's parent-side forwarding transport.
	UpstreamProxyFlag = "upstream-proxy"
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
	UpstreamProxy      serpent.String         `yaml:"upstream_proxy"`
	PprofEnabled       serpent.Bool           `yaml:"pprof_enabled"`
	PprofPort          serpent.Int64          `yaml:"pprof_port"`
	JailType           serpent.String         `yaml:"jail_type"`
	UseRealDNS         serpent.Bool           `yaml:"use_real_dns"`
	NoUserNamespace    serpent.Bool           `yaml:"no_user_namespace"`
	DisableAuditLogs   serpent.Bool           `yaml:"disable_audit_logs"`
	LogProxySocketPath serpent.String         `yaml:"log_proxy_socket_path"`

	// Session correlation header injection.
	SessionCorrelationEnabled serpent.Bool        `yaml:"session_correlation_enabled"`
	InjectSessionIDTarget     AllowStringsArray   `yaml:"-"`                         // From CLI flags only
	InjectSessionIDTargets    serpent.StringArray `yaml:"session_id_inject_targets"` // From config file
}

type AppConfig struct {
	AllowRules         []string
	LogLevel           string
	LogDir             string
	ProxyPort          int64
	UpstreamProxy      string `json:"-"`
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

	// ConfinedProcessName is the base name of the process boundary is
	// confining (e.g. "claude", "codex"), derived from TargetCMD. It is
	// reported alongside audit logs so that sessions can be attributed to
	// the process that generated them.
	ConfinedProcessName string
}

// confinedProcessName returns a human-readable name for the process being
// confined, derived from the first element of the target command. It returns
// an empty string when no command is present.
func confinedProcessName(targetCMD []string) string {
	if len(targetCMD) == 0 {
		return ""
	}
	return filepath.Base(targetCMD[0])
}

// StripUpstreamProxyArgs removes Boundary's parent-only upstream proxy flag
// before argv is passed to the confined child helper process.
func StripUpstreamProxyArgs(args []string) []string {
	stripped := make([]string, 0, len(args))
	flag := "--" + UpstreamProxyFlag
	flagWithValue := flag + "="

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			stripped = append(stripped, args[i:]...)
			return stripped
		}
		if arg == flag {
			if i+1 < len(args) {
				i++
			}
			continue
		}
		if strings.HasPrefix(arg, flagWithValue) {
			continue
		}
		stripped = append(stripped, arg)
	}

	return stripped
}

func NewAppConfigFromCliConfig(cfg CliConfig, targetCMD []string, environ []string) (AppConfig, error) {
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
	sc, err := buildSessionCorrelation(cfg, environ)
	if err != nil {
		return AppConfig{}, fmt.Errorf("session correlation config: %w", err)
	}

	upstreamProxy, err := normalizeUpstreamProxy(cfg.UpstreamProxy.Value(), cfg.ProxyPort.Value())
	if err != nil {
		return AppConfig{}, err
	}

	return AppConfig{
		AllowRules:          allAllowStrings,
		LogLevel:            cfg.LogLevel.Value(),
		LogDir:              cfg.LogDir.Value(),
		ProxyPort:           cfg.ProxyPort.Value(),
		UpstreamProxy:       upstreamProxy,
		PprofEnabled:        cfg.PprofEnabled.Value(),
		PprofPort:           cfg.PprofPort.Value(),
		JailType:            jailType,
		UseRealDNS:          cfg.UseRealDNS.Value(),
		NoUserNamespace:     cfg.NoUserNamespace.Value(),
		TargetCMD:           targetCMD,
		UserInfo:            userInfo,
		DisableAuditLogs:    cfg.DisableAuditLogs.Value(),
		LogProxySocketPath:  cfg.LogProxySocketPath.Value(),
		SessionCorrelation:  sc,
		ConfinedProcessName: confinedProcessName(targetCMD),
	}, nil
}

func normalizeUpstreamProxy(raw string, boundaryProxyPort int64) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}

	upstreamURL, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid upstream proxy URL")
	}
	if upstreamURL.Scheme != "http" && upstreamURL.Scheme != "https" {
		return "", fmt.Errorf("upstream proxy URL must use http or https scheme")
	}
	if upstreamURL.Hostname() == "" {
		return "", fmt.Errorf("upstream proxy URL must include a host")
	}
	if hasInvalidPort(upstreamURL) || hasOutOfRangePort(upstreamURL) {
		return "", fmt.Errorf("upstream proxy URL has an invalid port")
	}
	if pointsToBoundaryProxy(upstreamURL, boundaryProxyPort) {
		return "", fmt.Errorf("upstream proxy URL must not point to boundary's local proxy listener")
	}

	return upstreamURL.String(), nil
}

func hasInvalidPort(upstreamURL *url.URL) bool {
	if upstreamURL.Port() != "" {
		return false
	}

	host := upstreamURL.Host
	if strings.HasPrefix(host, "[") {
		bracket := strings.LastIndex(host, "]")
		return bracket >= 0 && len(host) > bracket+1
	}

	return strings.Count(host, ":") > 0
}

func hasOutOfRangePort(upstreamURL *url.URL) bool {
	port := upstreamURL.Port()
	if port == "" {
		return false
	}

	portNumber, err := strconv.Atoi(port)
	return err != nil || portNumber < 1 || portNumber > 65535
}

func pointsToBoundaryProxy(upstreamURL *url.URL, boundaryProxyPort int64) bool {
	port := upstreamURL.Port()
	if port == "" {
		port = defaultPortForScheme(upstreamURL.Scheme)
	}
	if port == "" || port != strconv.FormatInt(boundaryProxyPort, 10) {
		return false
	}

	host := strings.ToLower(upstreamURL.Hostname())
	if host == "localhost" {
		return true
	}

	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsUnspecified())
}

func defaultPortForScheme(scheme string) string {
	switch scheme {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}

// buildSessionCorrelation merges CLI and YAML inject target sources
// and validates the resulting configuration. Inject targets use the same
// "domain=... path=..." syntax as --allow rules so that matching semantics
// are identical. environ is passed explicitly (rather than reading
// os.Environ inside) so that callers and tests can supply a controlled
// environment.
func buildSessionCorrelation(cfg CliConfig, environ []string) (SessionCorrelationConfig, error) {
	// Merge YAML targets with CLI targets.
	targets := append(cfg.InjectSessionIDTargets.Value(), cfg.InjectSessionIDTarget.Value()...)

	if len(targets) == 0 && cfg.SessionCorrelationEnabled.Value() {
		if derived := DefaultInjectTargetsFromEnv(environ); len(derived) > 0 {
			targets = derived
		}
	}

	sc := SessionCorrelationConfig{
		Enabled:       cfg.SessionCorrelationEnabled.Value(),
		InjectTargets: targets,
	}

	if err := ValidateSessionCorrelation(sc); err != nil {
		return SessionCorrelationConfig{}, err
	}

	return sc, nil
}
