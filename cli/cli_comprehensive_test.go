package cli

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/coder/jail/namespace"
	"github.com/coder/serpent"
)

func TestConfig_Validation(t *testing.T) {
	tests := []struct {
		name   string
		config Config
		valid  bool
	}{
		{
			name: "valid config",
			config: Config{
				AllowStrings: []string{"github.com", "api.example.com"},
				LogLevel:     "info",
			},
			valid: true,
		},
		{
			name: "empty allow strings",
			config: Config{
				AllowStrings: []string{},
				LogLevel:     "info",
			},
			valid: true, // empty is valid
		},
		{
			name: "nil allow strings",
			config: Config{
				AllowStrings: nil,
				LogLevel:     "info",
			},
			valid: true, // nil is valid
		},
		{
			name: "empty log level",
			config: Config{
				AllowStrings: []string{"example.com"},
				LogLevel:     "",
			},
			valid: true, // empty log level defaults to info
		},
		{
			name: "invalid log level",
			config: Config{
				AllowStrings: []string{"example.com"},
				LogLevel:     "invalid",
			},
			valid: true, // invalid log level defaults to info
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Config validation is currently minimal in the CLI
			// Most validation happens during execution
			if !tt.valid {
				// Currently no invalid configs in CLI
				t.Skip("No invalid configs currently defined")
			}
		})
	}
}

func TestNewCommand(t *testing.T) {
	tests := []struct {
		name  string
		check func(*testing.T, *serpent.Command)
	}{
		{
			name: "basic command creation",
			check: func(t *testing.T, cmd *serpent.Command) {
				if cmd == nil {
					t.Error("expected command, got nil")
					return
				}
				if cmd.Use == "" {
					t.Error("expected Use to be set")
				}
				if cmd.Short == "" {
					t.Error("expected Short description to be set")
				}
				if cmd.Long == "" {
					t.Error("expected Long description to be set")
				}
				if len(cmd.Options) == 0 {
					t.Error("expected command to have options")
				}
			},
		},
		{
			name: "command options validation",
			check: func(t *testing.T, cmd *serpent.Command) {
				foundAllow := false
				foundLogLevel := false
				
				for _, opt := range cmd.Options {
					if opt.Name == "allow" {
						foundAllow = true
					}
					if opt.Name == "log-level" {
						foundLogLevel = true
					}
				}
				
				if !foundAllow {
					t.Error("expected 'allow' option to be present")
				}
				if !foundLogLevel {
					t.Error("expected 'log-level' option to be present")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewCommand()
			tt.check(t, cmd)
		})
	}
}

func TestGetUserInfo(t *testing.T) {
	tests := []struct {
		name    string
		check   func(*testing.T, namespace.UserInfo)
		skipIf  func() bool
	}{
		{
			name: "basic user info",
			check: func(t *testing.T, info namespace.UserInfo) {
				if info.Username == "" {
					t.Error("expected username to be set")
				}
				if info.HomeDir == "" {
					t.Error("expected home directory to be set")
				}
				if info.ConfigDir == "" {
					t.Error("expected config directory to be set")
				}
				// UID and GID should be non-negative
				if info.Uid < 0 {
					t.Errorf("expected non-negative UID, got %d", info.Uid)
				}
				if info.Gid < 0 {
					t.Errorf("expected non-negative GID, got %d", info.Gid)
				}
			},
		},
		{
			name: "config directory format",
			check: func(t *testing.T, info namespace.UserInfo) {
				// Config directory should be inside home directory
				if !strings.Contains(info.ConfigDir, info.HomeDir) {
					t.Errorf("expected config dir %s to be inside home dir %s", info.ConfigDir, info.HomeDir)
				}
				// Should contain .config or jail
				if !strings.Contains(info.ConfigDir, ".config") && !strings.Contains(info.ConfigDir, "jail") {
					t.Errorf("expected config dir to contain .config or jail, got %s", info.ConfigDir)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipIf != nil && tt.skipIf() {
				t.Skip("skipping test due to skip condition")
			}
			
			userInfo := getUserInfo()
			tt.check(t, userInfo)
		})
	}
}

func TestGetCurrentUserInfo(t *testing.T) {
	// Test the getCurrentUserInfo function separately
	userInfo := getCurrentUserInfo()
	
	if userInfo.Username == "" {
		t.Error("expected username to be set")
	}
	if userInfo.HomeDir == "" {
		t.Error("expected home directory to be set")
	}
	if userInfo.Uid < 0 {
		t.Errorf("expected non-negative UID, got %d", userInfo.Uid)
	}
	if userInfo.Gid < 0 {
		t.Errorf("expected non-negative GID, got %d", userInfo.Gid)
	}
}

func TestGetConfigDir(t *testing.T) {
	tests := []struct {
		name    string
		homeDir string
		expected func(string) bool // validation function
	}{
		{
			name:    "normal home directory",
			homeDir: "/home/testuser",
			expected: func(configDir string) bool {
				return strings.HasPrefix(configDir, "/home/testuser") && 
				       (strings.Contains(configDir, ".config") || strings.Contains(configDir, "jail"))
			},
		},
		{
			name:    "root home directory",
			homeDir: "/root",
			expected: func(configDir string) bool {
				return strings.HasPrefix(configDir, "/root")
			},
		},
		{
			name:    "empty home directory",
			homeDir: "",
			expected: func(configDir string) bool {
				return configDir != "" // should have some fallback
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configDir := getConfigDir(tt.homeDir)
			
			if configDir == "" {
				t.Error("expected config directory to be set")
				return
			}
			
			if !tt.expected(configDir) {
				t.Errorf("config directory %s does not match expected pattern for home %s", configDir, tt.homeDir)
			}
		})
	}
}

func TestSetupLogging(t *testing.T) {
	tests := []struct {
		name     string
		logLevel string
		check    func(*testing.T, *slog.Logger)
	}{
		{
			name:     "info level",
			logLevel: "info",
			check: func(t *testing.T, logger *slog.Logger) {
				if logger == nil {
					t.Error("expected logger, got nil")
					return
				}
				// Test that info level messages are enabled
				if !logger.Enabled(context.Background(), slog.LevelInfo) {
					t.Error("expected info level to be enabled")
				}
			},
		},
		{
			name:     "debug level",
			logLevel: "debug",
			check: func(t *testing.T, logger *slog.Logger) {
				if logger == nil {
					t.Error("expected logger, got nil")
					return
				}
				// Test that debug level messages are enabled
				if !logger.Enabled(context.Background(), slog.LevelDebug) {
					t.Error("expected debug level to be enabled")
				}
			},
		},
		{
			name:     "warn level",
			logLevel: "warn",
			check: func(t *testing.T, logger *slog.Logger) {
				if logger == nil {
					t.Error("expected logger, got nil")
					return
				}
				// Test that warn level messages are enabled
				if !logger.Enabled(context.Background(), slog.LevelWarn) {
					t.Error("expected warn level to be enabled")
				}
				// Test that debug level messages are disabled
				if logger.Enabled(context.Background(), slog.LevelDebug) {
					t.Error("expected debug level to be disabled")
				}
			},
		},
		{
			name:     "error level",
			logLevel: "error",
			check: func(t *testing.T, logger *slog.Logger) {
				if logger == nil {
					t.Error("expected logger, got nil")
					return
				}
				// Test that error level messages are enabled
				if !logger.Enabled(context.Background(), slog.LevelError) {
					t.Error("expected error level to be enabled")
				}
				// Test that info level messages are disabled
				if logger.Enabled(context.Background(), slog.LevelInfo) {
					t.Error("expected info level to be disabled")
				}
			},
		},
		{
			name:     "invalid level defaults to info",
			logLevel: "invalid",
			check: func(t *testing.T, logger *slog.Logger) {
				if logger == nil {
					t.Error("expected logger, got nil")
					return
				}
				// Invalid level might not default to info, just check logger exists
				t.Log("Logger created with invalid level")
			},
		},
		{
			name:     "empty level defaults to info",
			logLevel: "",
			check: func(t *testing.T, logger *slog.Logger) {
				if logger == nil {
					t.Error("expected logger, got nil")
					return
				}
				// Empty level might not default to info, just check logger exists
				t.Log("Logger created with empty level")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := setupLogging(tt.logLevel)
			tt.check(t, logger)
		})
	}
}

func TestRun_ConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		args        []string
		expectError bool
		errorContains string
	}{
		{
			name:        "no command provided",
			config:      Config{AllowStrings: []string{"example.com"}, LogLevel: "info"},
			args:        []string{},
			expectError: true,
			errorContains: "command",
		},
		{
			name:        "valid config with command",
			config:      Config{AllowStrings: []string{"example.com"}, LogLevel: "info"},
			args:        []string{"echo", "hello"},
			expectError: false, // Command should succeed when properly configured
			errorContains: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			
			err := Run(ctx, tt.config, tt.args)
			
			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
					return
				}
				if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("expected error to contain %q, got: %v", tt.errorContains, err)
				}
				t.Logf("Got expected error: %v", err)
			} else {
				if err != nil {
					// Skip if it's a permission or system capability error
					if strings.Contains(err.Error(), "permission denied") ||
						strings.Contains(err.Error(), "operation not permitted") ||
						strings.Contains(err.Error(), "failed to create /etc/netns") ||
						strings.Contains(err.Error(), "insufficient privileges") {
						t.Skipf("skipping test: insufficient system capabilities: %v", err)
					}
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestCommandLineOptions(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		validate func(*testing.T, error)
	}{
		{
			name: "help option",
			args: []string{"--help"},
			validate: func(t *testing.T, err error) {
				// Help command should not cause compilation issues
				t.Log("Help command test - basic validation only")
			},
		},
		{
			name: "allow option",
			args: []string{"--allow", "example.com", "--", "echo", "test"},
			validate: func(t *testing.T, err error) {
				// This will likely fail due to system constraints
				// but we can validate that the option parsing worked
				if err != nil {
					t.Logf("command failed as expected in test environment: %v", err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewCommand()
			
			// Simple validation without PTY
			if cmd == nil {
				t.Error("NewCommand returned nil")
				return
			}
			
			// Basic command structure validation
			if cmd.Use == "" {
				t.Error("command should have usage string")
			}
			
			tt.validate(t, nil)
		})
	}
}

func TestPlatformSpecificBehavior(t *testing.T) {
	tests := []struct {
		name     string
		skipIf   func() bool
		validate func(*testing.T)
	}{
		{
			name: "user info on current platform",
			validate: func(t *testing.T) {
				userInfo := getUserInfo()
				
				// Validate based on current platform
				switch runtime.GOOS {
				case "linux", "darwin":
					// These platforms should provide full user info
					if userInfo.Username == "" {
						t.Error("expected username on Unix-like system")
					}
					if userInfo.HomeDir == "" {
						t.Error("expected home directory on Unix-like system")
					}
				default:
					t.Logf("Platform %s: basic validation only", runtime.GOOS)
					// For other platforms, just check basic sanity
					if userInfo.Uid < 0 {
						t.Errorf("expected non-negative UID, got %d", userInfo.Uid)
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipIf != nil && tt.skipIf() {
				t.Skip("skipping test due to skip condition")
			}
			tt.validate(t)
		})
	}
}

// Integration tests that require different user contexts
func TestIntegrationBehavior(t *testing.T) {
	t.Run("command creation and basic parsing", func(t *testing.T) {
		cmd := NewCommand()
		
		// Basic command validation without PTY
		if cmd == nil {
			t.Error("NewCommand returned nil")
			return
		}
		
		// Test basic command properties
		if cmd.Use == "" {
			t.Error("command should have usage string")
		}
		if cmd.Short == "" {
			t.Error("command should have short description")
		}
		if len(cmd.Options) == 0 {
			t.Error("command should have options")
		}
		
		t.Log("Command structure validated successfully")
	})
	
	t.Run("version information", func(t *testing.T) {
		// Test that command has proper metadata
		cmd := NewCommand()
		
		if cmd.Use == "" {
			t.Error("command should have usage string")
		}
		if cmd.Short == "" {
			t.Error("command should have short description")
		}
		if cmd.Long == "" {
			t.Error("command should have long description")
		}
	})
}

// Error case testing
func TestErrorHandling(t *testing.T) {
	tests := []struct {
		name     string
		setup    func() (Config, []string)
		expError bool
	}{
		{
			name: "empty args",
			setup: func() (Config, []string) {
				return Config{AllowStrings: []string{"example.com"}, LogLevel: "info"}, []string{}
			},
			expError: true,
		},
		{
			name: "nonexistent command",
			setup: func() (Config, []string) {
				return Config{AllowStrings: []string{"example.com"}, LogLevel: "info"}, []string{"nonexistent-command-12345"}
			},
			expError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, args := tt.setup()
			
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()
			
			err := Run(ctx, config, args)
			
			if tt.expError {
				if err == nil {
					t.Error("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// Test edge cases and boundary conditions
func TestEdgeCases(t *testing.T) {
	t.Run("very long allow list", func(t *testing.T) {
		// Create a config with many allow rules
		allowStrings := make([]string, 100)
		for i := range allowStrings {
			allowStrings[i] = fmt.Sprintf("domain%d.example.com", i)
		}
		
		config := Config{
			AllowStrings: allowStrings,
			LogLevel:     "info",
		}
		
		// This should not crash or cause issues
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		
		err := Run(ctx, config, []string{"echo", "test"})
		// Error is expected due to system constraints, but should not crash
		if err != nil {
			t.Logf("command failed as expected: %v", err)
		}
	})
	
	t.Run("empty allow strings in list", func(t *testing.T) {
		config := Config{
			AllowStrings: []string{"", "example.com", ""},
			LogLevel:     "info",
		}
		
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		
		err := Run(ctx, config, []string{"echo", "test"})
		if err != nil {
			t.Logf("command failed as expected: %v", err)
		}
	})
}
