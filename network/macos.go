//go:build darwin

package network

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/coder/jail/environment"
)

const (
	PF_ANCHOR_NAME = "network"
	GROUP_NAME     = "network"
)

// MacOSNetJail implements network jail using macOS PF (Packet Filter) and group-based isolation
type MacOSNetJail struct {
	config        JailConfig
	groupID       int
	pfRulesPath   string
	mainRulesPath string
	logger        *slog.Logger
}

// newMacOSJail creates a new macOS network jail instance
func newMacOSJail(config JailConfig, logger *slog.Logger) (*MacOSNetJail, error) {
	pfRulesPath := fmt.Sprintf("/tmp/%s.pf", config.NetJailName)
	mainRulesPath := fmt.Sprintf("/tmp/%s_main.pf", config.NetJailName)

	return &MacOSNetJail{
		config:        config,
		pfRulesPath:   pfRulesPath,
		mainRulesPath: mainRulesPath,
		logger:        logger,
	}, nil
}

// Setup configures PF rules and creates the network jail group
func (m *MacOSNetJail) Setup(httpPort, httpsPort int) error {
	m.logger.Debug("Setup called", "httpPort", httpPort, "httpsPort", httpsPort)
	m.config.HTTPPort = httpPort
	m.config.HTTPSPort = httpsPort

	// Create or get network jail group
	m.logger.Debug("Creating or ensuring network jail group")
	if err := m.ensureGroup(); err != nil {
		return fmt.Errorf("failed to ensure group: %v", err)
	}
	m.logger.Debug("Network jail group ready", "groupID", m.groupID)

	// Setup PF rules
	m.logger.Debug("Setting up PF rules")
	if err := m.setupPFRules(); err != nil {
		return fmt.Errorf("failed to setup PF rules: %v", err)
	}
	m.logger.Debug("PF rules setup completed")

	m.logger.Debug("Setup completed successfully")
	return nil
}

// Execute runs the command with the network jail group membership
func (m *MacOSNetJail) Execute(command []string, extraEnv map[string]string) error {
	m.logger.Debug("Execute called", "command", command)
	if len(command) == 0 {
		return fmt.Errorf("no command specified")
	}

	// Create command directly (no sg wrapper needed)
	m.logger.Debug("Creating command with group membership", "groupID", m.groupID)
	cmd := exec.Command(command[0], command[1:]...)
	m.logger.Debug("Full command args", "args", command)

	// Set up environment
	m.logger.Debug("Setting up environment")
	env := os.Environ()

	// Restore original user environment if running under sudo
	restoredUserEnv := environment.RestoreOriginalUserEnvironment(m.logger)
	for key, value := range restoredUserEnv {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}

	// Add extra environment variables (including CA cert if provided)
	for key, value := range extraEnv {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}

	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	// Set group ID using syscall (like httpjail does)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Gid: uint32(m.groupID),
		},
	}

	// Start and wait for command to complete
	m.logger.Debug("Starting command", "path", cmd.Path, "args", cmd.Args)
	err := cmd.Start()
	if err != nil {
		return fmt.Errorf("failed to start command: %v", err)
	}
	m.logger.Debug("Command started, waiting for completion")

	// Wait for command to complete
	err = cmd.Wait()
	m.logger.Debug("Command completed", "error", err)
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			if status, ok := exitError.Sys().(syscall.WaitStatus); ok {
				m.logger.Debug("Command exit status", "status", status.ExitStatus())
				os.Exit(status.ExitStatus())
			}
		}
		return fmt.Errorf("command execution failed: %v", err)
	}

	m.logger.Debug("Command executed successfully")
	return nil
}

// Cleanup removes PF rules and cleans up temporary files
func (m *MacOSNetJail) Cleanup() error {
	m.logger.Debug("Starting cleanup process")
	if m.config.SkipCleanup {
		m.logger.Debug("Skipping cleanup (SkipCleanup=true)")
		return nil
	}

	// Remove PF rules
	m.logger.Debug("Removing PF rules")
	if err := m.removePFRules(); err != nil {
		return fmt.Errorf("failed to remove PF rules: %v", err)
	}

	// Clean up temporary files
	m.logger.Debug("Cleaning up temporary files")
	m.cleanupTempFiles()

	m.logger.Debug("Cleanup completed successfully")
	return nil
}

// ensureGroup creates the network jail group if it doesn't exist
func (m *MacOSNetJail) ensureGroup() error {
	// Check if group already exists
	output, err := exec.Command("dscl", ".", "-read", fmt.Sprintf("/Groups/%s", GROUP_NAME), "PrimaryGroupID").Output()
	if err == nil {
		// Parse GID from output
		stdout := string(output)
		for _, line := range strings.Split(stdout, "\n") {
			if strings.Contains(line, "PrimaryGroupID") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					gid, err := strconv.Atoi(parts[len(parts)-1])
					if err != nil {
						return fmt.Errorf("failed to parse GID: %v", err)
					}
					m.groupID = gid
					return nil
				}
			}
		}
	}

	// Group doesn't exist, create it
	cmd := exec.Command("dseditgroup", "-o", "create", GROUP_NAME)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create group: %v", err)
	}

	// Get the newly created group's GID
	output, err = exec.Command("dscl", ".", "-read", fmt.Sprintf("/Groups/%s", GROUP_NAME), "PrimaryGroupID").Output()
	if err != nil {
		return fmt.Errorf("failed to read group GID: %v", err)
	}

	stdout := string(output)
	for _, line := range strings.Split(stdout, "\n") {
		if strings.Contains(line, "PrimaryGroupID") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				gid, err := strconv.Atoi(parts[len(parts)-1])
				if err != nil {
					return fmt.Errorf("failed to parse GID: %v", err)
				}
				m.groupID = gid
				return nil
			}
		}
	}

	return fmt.Errorf("failed to get GID for group %s", GROUP_NAME)
}

// getDefaultInterface gets the default network interface
func (m *MacOSNetJail) getDefaultInterface() (string, error) {
	output, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return "", fmt.Errorf("failed to get default route: %v", err)
	}

	stdout := string(output)
	for _, line := range strings.Split(stdout, "\n") {
		if strings.Contains(line, "interface:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1], nil
			}
		}
	}

	// Fallback to en0 if we can't determine
	return "en0", nil
}

// createPFRules creates PF rules for traffic diversion
func (m *MacOSNetJail) createPFRules() (string, error) {
	// Get the default network interface
	iface, err := m.getDefaultInterface()
	if err != nil {
		return "", fmt.Errorf("failed to get default interface: %v", err)
	}

	// Create PF rules following httpjail's working pattern
	rules := fmt.Sprintf(`# boundary PF rules for GID %d on interface %s
# First, redirect traffic arriving on lo0 to our proxy ports
rdr pass on lo0 inet proto tcp from any to any port 80 -> 127.0.0.1 port %d
rdr pass on lo0 inet proto tcp from any to any port 443 -> 127.0.0.1 port %d

# Route boundary group traffic to lo0 where it will be redirected
pass out route-to (lo0 127.0.0.1) inet proto tcp from any to any port 80 group %d keep state
pass out route-to (lo0 127.0.0.1) inet proto tcp from any to any port 443 group %d keep state

# Also handle traffic on the specific interface
pass out on %s route-to (lo0 127.0.0.1) inet proto tcp from any to any port 80 group %d keep state
pass out on %s route-to (lo0 127.0.0.1) inet proto tcp from any to any port 443 group %d keep state

# Allow all loopback traffic
pass on lo0 all
`,
		m.groupID,
		iface,
		m.config.HTTPPort,
		m.config.HTTPSPort,
		m.groupID,
		m.groupID,
		iface,
		m.groupID,
		iface,
		m.groupID,
	)

	return rules, nil
}

// setupPFRules configures packet filter rules to redirect traffic
func (m *MacOSNetJail) setupPFRules() error {
	// Create PF rules
	rules, err := m.createPFRules()
	if err != nil {
		return fmt.Errorf("failed to create PF rules: %v", err)
	}

	// Write rules to temp file
	if err := os.WriteFile(m.pfRulesPath, []byte(rules), 0644); err != nil {
		return fmt.Errorf("failed to write PF rules file: %v", err)
	}

	// Load rules into anchor
	cmd := exec.Command("pfctl", "-a", PF_ANCHOR_NAME, "-f", m.pfRulesPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to load PF rules: %v", err)
	}

	// Enable PF if not already enabled
	cmd = exec.Command("pfctl", "-E")
	cmd.Run() // Ignore error as PF might already be enabled

	// Create and load main ruleset that includes our anchor
	mainRules := fmt.Sprintf(`# Temporary main ruleset to include boundary anchor
# Include default Apple anchors (in required order)
# 1. Normalization
scrub-anchor "com.apple/*"
# 2. Queueing
dummynet-anchor "com.apple/*"
# 3. Translation (NAT/RDR)
nat-anchor "com.apple/*"
rdr-anchor "com.apple/*"
rdr-anchor "%s"
# 4. Filtering
anchor "com.apple/*"
anchor "%s"
`, PF_ANCHOR_NAME, PF_ANCHOR_NAME)

	// Write and load the main ruleset
	if err := os.WriteFile(m.mainRulesPath, []byte(mainRules), 0644); err != nil {
		return fmt.Errorf("failed to write main PF rules: %v", err)
	}

	cmd = exec.Command("pfctl", "-f", m.mainRulesPath)
	if err := cmd.Run(); err != nil {
		// Don't fail if main rules can't be loaded, but warn
		fmt.Fprintf(os.Stderr, "Warning: failed to load main PF rules: %v\n", err)
	}

	// Verify that rules were loaded correctly
	cmd = exec.Command("pfctl", "-a", PF_ANCHOR_NAME, "-s", "rules")
	output, err := cmd.Output()
	if err == nil && len(output) > 0 {
		// Rules loaded successfully
		return nil
	}

	return nil
}

// removePFRules removes PF rules from anchor
func (m *MacOSNetJail) removePFRules() error {
	// Flush the anchor
	cmd := exec.Command("pfctl", "-a", PF_ANCHOR_NAME, "-F", "all")
	cmd.Run() // Ignore errors during cleanup

	return nil
}

// cleanupTempFiles removes temporary rule files
func (m *MacOSNetJail) cleanupTempFiles() {
	if m.pfRulesPath != "" {
		os.Remove(m.pfRulesPath)
	}
	if m.mainRulesPath != "" {
		os.Remove(m.mainRulesPath)
	}
}