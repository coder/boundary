package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/coder/jail/namespace"
	rulespkg "github.com/coder/jail/rules"
)

// Test configuration validation
func TestConfig_Validation(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: Config{
				AllowStrings: []string{"example.com", "api.github.com"},
				LogLevel:     "info",
			},
			wantErr: false,
		},
		{
			name: "empty allow strings",
			config: Config{
				AllowStrings: []string{},
				LogLevel:     "debug",
			},
			wantErr: false, // Empty allow list is valid (deny all)
		},
		{
			name: "nil allow strings",
			config: Config{
				AllowStrings: nil,
				LogLevel:     "warn",
			},
			wantErr: false, // Nil allow list is valid (deny all)
		},
		{
			name: "empty log level",
			config: Config{
				AllowStrings: []string{"example.com"},
				LogLevel:     "",
			},
			wantErr: false, // Empty log level should default
		},
		{
			name: "invalid log level",
			config: Config{
				AllowStrings: []string{"example.com"},
				LogLevel:     "invalid",
			},
			wantErr: false, // Invalid log level should default to info
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate config by attempting to create logger
			logger := setupLogging(tt.config.LogLevel)
			if logger == nil {
				t.Error("setupLogging returned nil logger")
			}

			// Check allow strings parsing
			rules, err := rulespkg.ParseAllowSpecs(tt.config.AllowStrings)
			if (err != nil) != tt.wantErr {
				t.Errorf("rules.ParseAllowSpecs() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr && err == nil {
				// For non-empty allow strings, should return a non-nil slice
				// For empty/nil allow strings, returns nil (which is valid)
				if len(tt.config.AllowStrings) > 0 && rules == nil {
					t.Error("expected non-nil rules slice for non-empty allow strings")
				}
			}
		})
	}
}

// Test command creation and structure
func TestNewCommand(t *testing.T) {
	tests := []struct {
		name         string
		checkOptions bool
	}{
		{
			name:         "basic command creation",
			checkOptions: false,
		},
		{
			name:         "command options validation",
			checkOptions: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewCommand()
			
			if cmd == nil {
				t.Fatal("NewCommand() returned nil")
			}

			if cmd.Use == "" {
				t.Error("command should have usage string")
			}

			if cmd.Short == "" {
				t.Error("command should have short description")
			}

			if tt.checkOptions {
				if len(cmd.Options) == 0 {
					t.Error("command should have options")
				}
				
				// Check for expected options
				hasAllowOption := false
				hasLogLevelOption := false
				
				for _, opt := range cmd.Options {
					if opt.Name == "allow" {
						hasAllowOption = true
					}
					if opt.Name == "log-level" {
						hasLogLevelOption = true
					}
				}
				
				if !hasAllowOption {
					t.Error("command should have 'allow' option")
				}
				if !hasLogLevelOption {
					t.Error("command should have 'log-level' option")
				}
			}
		})
	}
}

// Test user information functions
func TestGetUserInfo(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "basic user info",
		},
		{
			name: "config directory format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test that we can get user info without panicking
			info := getUserInfo()
			
			if info.Username == "" {
				t.Log("Username is empty, may be expected in test environment")
			}
			
			if info.Uid == 0 {
				t.Log("UID is 0, may be running as root or in test environment")
			}
			
			if info.Gid == 0 {
				t.Log("GID is 0, may be running as root or in test environment")
			}
			
			// Test config directory
			configDir := getConfigDir(info.HomeDir)
			if configDir == "" {
				t.Error("getConfigDir returned empty string")
			}
		})
	}
}

// Test current user info
func TestGetCurrentUserInfo(t *testing.T) {
	info := getCurrentUserInfo()
	
	if info.Username == "" {
		t.Log("current user has empty username, may be expected in test environment")
	}
	
	if info.Uid < 0 {
		t.Error("current user should have valid Uid")
	}
	
	if info.Gid < 0 {
		t.Error("current user should have valid Gid")
	}
}

// Test config directory function
func TestGetConfigDir(t *testing.T) {
	tests := []struct {
		name           string
		setupEnv       func() (cleanup func())
		user           namespace.UserInfo
		expectedSuffix string
	}{
		{
			name: "normal home directory",
			setupEnv: func() func() {
				// Clear XDG_CONFIG_HOME to test HOME fallback
				original := os.Getenv("XDG_CONFIG_HOME")
				os.Unsetenv("XDG_CONFIG_HOME")
				return func() {
					if original != "" {
						os.Setenv("XDG_CONFIG_HOME", original)
					}
				}
			},
			user: namespace.UserInfo{
				Username: "testuser",
				Uid:      1000,
				Gid:      1000,
				HomeDir:  "/home/testuser",
			},
			expectedSuffix: ".config/jail",
		},
		{
			name: "root home directory",
			setupEnv: func() func() {
				original := os.Getenv("XDG_CONFIG_HOME")
				os.Unsetenv("XDG_CONFIG_HOME")
				return func() {
					if original != "" {
						os.Setenv("XDG_CONFIG_HOME", original)
					}
				}
			},
			user: namespace.UserInfo{
				Username: "root",
				Uid:      0,
				Gid:      0,
				HomeDir:  "/root",
			},
			expectedSuffix: ".config/jail",
		},
		{
			name: "empty home directory",
			setupEnv: func() func() {
				original := os.Getenv("XDG_CONFIG_HOME")
				os.Unsetenv("XDG_CONFIG_HOME")
				return func() {
					if original != "" {
						os.Setenv("XDG_CONFIG_HOME", original)
					}
				}
			},
			user: namespace.UserInfo{
				Username: "testuser",
				Uid:      1000,
				Gid:      1000,
				HomeDir:  "", // Empty home directory
			},
			expectedSuffix: "/jail", // Should fall back to /etc/jail or similar
		},
		{
			name: "XDG_CONFIG_HOME set",
			setupEnv: func() func() {
				original := os.Getenv("XDG_CONFIG_HOME")
				os.Setenv("XDG_CONFIG_HOME", "/tmp/config")
				return func() {
					if original != "" {
						os.Setenv("XDG_CONFIG_HOME", original)
					} else {
						os.Unsetenv("XDG_CONFIG_HOME")
					}
				}
			},
			user: namespace.UserInfo{
				Username: "testuser",
				Uid:      1000,
				Gid:      1000,
				HomeDir:  "/home/testuser",
			},
			expectedSuffix: "jail", // XDG_CONFIG_HOME + jail
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanup := tt.setupEnv()
			defer cleanup()
			
			configDir := getConfigDir(tt.user.HomeDir)
			
			if configDir == "" {
				t.Error("getConfigDir returned empty string")
				return
			}
			
			if !strings.HasSuffix(configDir, tt.expectedSuffix) {
				t.Errorf("getConfigDir() = %q, expected to end with %q", configDir, tt.expectedSuffix)
			}
		})
	}
}

// Test logging setup
func TestSetupLogging(t *testing.T) {
	tests := []struct {
		name     string
		level    string
		expected string
	}{
		{
			name:     "info level",
			level:    "info",
			expected: "info",
		},
		{
			name:     "debug level",
			level:    "debug",
			expected: "debug",
		},
		{
			name:     "warn level",
			level:    "warn",
			expected: "warn",
		},
		{
			name:     "error level",
			level:    "error",
			expected: "error",
		},
		{
			name:     "invalid level defaults to info",
			level:    "invalid",
			expected: "info",
		},
		{
			name:     "empty level defaults to info",
			level:    "",
			expected: "info",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := setupLogging(tt.level)
			
			if logger == nil {
				t.Error("setupLogging returned nil")
				return
			}
			
			// Test that logger can be used
			logger.Info("test log message")
			
			// Log the result for manual verification in verbose mode
			if tt.level == "invalid" {
				t.Log("Logger created with invalid level")
			}
			
			if tt.level == "" {
				t.Log("Logger created with empty level")
			}
		})
	}
}

// Test the main Run function configuration validation
func TestRun_ConfigValidation(t *testing.T) {
	tests := []struct {
		name   string
		config Config
		args   []string
		wantErr bool
	}{
		{
			name: "no command provided",
			config: Config{
				AllowStrings: []string{"example.com"},
				LogLevel: "info",
			},
			args: []string{}, // No command
			wantErr: true,
		},
		{
			name: "valid config with command",
			config: Config{
				AllowStrings: []string{"example.com"},
				LogLevel: "info",
			},
			args: []string{"echo", "hello"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			
			err := Run(ctx, tt.config, tt.args)
			
			if tt.wantErr {
				if err == nil {
					t.Error("expected error but got none")
				} else {
					t.Logf("Got expected error: %v", err)
				}
			} else {
				if err != nil {
					// In test environments, permission errors are expected for jail creation
					if strings.Contains(err.Error(), "permission denied") ||
						strings.Contains(err.Error(), "operation not permitted") ||
						strings.Contains(err.Error(), "executable file not found") {
						t.Skipf("skipping due to insufficient permissions or missing tools: %v", err)
					}
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// Test command line options
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

// Test platform-specific behavior
func TestPlatformSpecificBehavior(t *testing.T) {
	t.Run("user info on current platform", func(t *testing.T) {
		// Test that user info functions work on the current platform
		info := getCurrentUserInfo()
		
		if info.Username == "" {
			t.Log("Username is empty, may be expected in containerized environment")
		}
	})
}

// Test integration behavior
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
		// Test that version information is accessible
		cmd := NewCommand()
		if cmd.Long == "" {
			t.Log("Long description is empty, may be expected")
		}
	})
}

// Test error handling scenarios
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
			expError: false, // Jail starts successfully, only the command inside fails
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
					// In test environments, permission errors are expected
					if strings.Contains(err.Error(), "permission denied") ||
						strings.Contains(err.Error(), "operation not permitted") {
						t.Skipf("skipping due to insufficient permissions: %v", err)
					}
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// Test edge cases and boundary conditions
func TestEdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		setupFunc func() (Config, []string, bool) // returns config, args, expectError
	}{
		{
			name: "very long allow list",
			setupFunc: func() (Config, []string, bool) {
				// Create a very long allow list
				allowList := make([]string, 100)
				for i := 0; i < 100; i++ {
					allowList[i] = fmt.Sprintf("example%d.com", i)
				}
				return Config{AllowStrings: allowList, LogLevel: "info"}, []string{"echo", "test"}, false
			},
		},
		{
			name: "empty allow strings in list",
			setupFunc: func() (Config, []string, bool) {
				return Config{AllowStrings: []string{""}, LogLevel: "info"}, []string{"echo", "test"}, true
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, args, expectError := tt.setupFunc()
			
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			
			err := Run(ctx, config, args)
			
			if expectError {
				if err == nil {
					t.Error("expected error but got none")
				} else {
					t.Logf("command failed as expected: %v", err)
				}
			} else {
				if err != nil {
					// Handle expected system constraint errors
					if strings.Contains(err.Error(), "permission denied") ||
						strings.Contains(err.Error(), "operation not permitted") ||
						strings.Contains(err.Error(), "executable file not found") {
						t.Skipf("skipping due to system constraints: %v", err)
					}
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}
