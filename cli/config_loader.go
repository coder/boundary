package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type fileConfig struct {
	Allow     []string `yaml:"allow"`
	LogLevel  string   `yaml:"log_level"`
	LogDir    string   `yaml:"log_dir"`
	ProxyPort int64    `yaml:"proxy_port"`
	Pprof     struct {
		Enabled bool  `yaml:"enabled"`
		Port    int64 `yaml:"port"`
	} `yaml:"pprof"`
}

func loadConfigFile(configPath string) (fileConfig, string, error) {
	var cfg fileConfig
	path, err := resolveConfigPath(configPath)
	if err != nil {
		return cfg, "", err
	}
	if path == "" {
		return cfg, "", nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, "", fmt.Errorf("failed to read config file %s: %v", path, err)
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return cfg, "", fmt.Errorf("failed to parse YAML in %s: %v", path, err)
	}
	return cfg, path, nil
}

// loadAndMergeConfig loads YAML config (if any) and merges with CLI config, returning the merged Config and the file path used.
func loadAndMergeConfig(cliCfg Config) (Config, string, error) {
	fileCfg, filePath, err := loadConfigFile(cliCfg.ConfigPath)
	if err != nil {
		return Config{}, "", err
	}
	merged, err := mergeConfig(fileCfg, cliCfg)
	if err != nil {
		return Config{}, filePath, err
	}
	return merged, filePath, nil
}

func resolveConfigPath(configPath string) (string, error) {
	if configPath != "" {
		return configPath, nil
	}
	// Default: ~/.config/coder_boundary/config.yaml (same base as cert storage)
	h, err := os.UserHomeDir()
	if err != nil {
		return "", nil
	}
	path := filepath.Join(h, ".config", "coder_boundary", "config.yaml")
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}
	return "", nil
}

// mergeConfig applies CLI over file config (CLI wins), with allow exclusivity enforced.
// Returns final merged Config with AllowStrings set from the single allowed source.
func mergeConfig(file fileConfig, cliCfg Config) (Config, error) {
	// Enforce allow exclusivity
	if len(file.Allow) > 0 && len(cliCfg.AllowStrings) > 0 {
		return Config{}, errors.New("allow rules specified in both config file and CLI; specify in only one source")
	}

	final := cliCfg

	// Fill from file where CLI left zero values
	if final.LogLevel == "" && file.LogLevel != "" {
		final.LogLevel = file.LogLevel
	}
	if final.LogDir == "" && file.LogDir != "" {
		final.LogDir = file.LogDir
	}
	if final.ProxyPort == 0 && file.ProxyPort != 0 {
		final.ProxyPort = file.ProxyPort
	}
	// pprof
	if !final.PprofEnabled && file.Pprof.Enabled {
		final.PprofEnabled = true
	}
	if final.PprofPort == 0 && file.Pprof.Port != 0 {
		final.PprofPort = file.Pprof.Port
	}

	// Choose allow from the only specified source and set on final config
	if len(final.AllowStrings) == 0 && len(file.Allow) > 0 {
		final.AllowStrings = file.Allow
	}

	return final, nil
}
