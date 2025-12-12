package config

import (
	"github.com/coder/serpent"
)

type CliConfig struct {
	Config                           serpent.YAMLConfigPath `yaml:"-"`
	AllowListStrings                 serpent.StringArray    `yaml:"allowlist"` // From config file
	AllowStrings                     serpent.StringArray    `yaml:"-"`         // From CLI flags only
	LogLevel                         serpent.String         `yaml:"log_level"`
	LogDir                           serpent.String         `yaml:"log_dir"`
	ProxyPort                        serpent.Int64          `yaml:"proxy_port"`
	PprofEnabled                     serpent.Bool           `yaml:"pprof_enabled"`
	PprofPort                        serpent.Int64          `yaml:"pprof_port"`
	ConfigureDNSForLocalStubResolver serpent.Bool           `yaml:"configure_dns_for_local_stub_resolver"`
}

type AppConfig struct {
	AllowRules                       []string
	LogLevel                         string
	LogDir                           string
	ProxyPort                        int64
	PprofEnabled                     bool
	PprofPort                        int64
	ConfigureDNSForLocalStubResolver bool
}

func NewAppConfigFromCliConfig(cfg CliConfig) AppConfig {
	// Merge allowlist from config file with allow from CLI flags
	allowListStrings := cfg.AllowListStrings.Value()
	allowStrings := cfg.AllowStrings.Value()

	// Combine allowlist (config file) with allow (CLI flags)
	allAllowStrings := append(allowListStrings, allowStrings...)

	return AppConfig{
		AllowRules:                       allAllowStrings,
		LogLevel:                         cfg.LogLevel.Value(),
		LogDir:                           cfg.LogDir.Value(),
		ProxyPort:                        cfg.ProxyPort.Value(),
		PprofEnabled:                     cfg.PprofEnabled.Value(),
		PprofPort:                        cfg.PprofPort.Value(),
		ConfigureDNSForLocalStubResolver: cfg.ConfigureDNSForLocalStubResolver.Value(),
	}
}
