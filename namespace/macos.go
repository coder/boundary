//go:build darwin

package namespace

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
)

const (
	pfAnchorName = "coder_jail"
	groupName    = "coder_jail"
)

// MacOSNetJail implements network jail using macOS PF (Packet Filter) and group-based isolation
type MacOSNetJail struct {
	config        Config
	groupID       int
	pfRulesPath   string
	mainRulesPath string
	logger        *slog.Logger
}

// newMacOSJail creates a new macOS network jail instance
func newMacOSJail(config Config, logger *slog.Logger) (*MacOSNetJail, error) {
	ns := newNamespaceName()
	pfRulesPath := fmt.Sprintf("/tmp/%s.pf", ns)
	mainRulesPath := fmt.Sprintf("/tmp/%s_main.pf", ns)

	return &MacOSNetJail{
		config:        config,
		pfRulesPath:   pfRulesPath,
		mainRulesPath: mainRulesPath,
		logger:        logger,
	}, nil
}

// Setup creates the network jail group and configures PF rules
func (m *MacOSNetJail) Open() error {
	m.logger.Debug("Setup called")

	// Create or get network jail group
	m.logger.Debug("Creating or ensuring network jail group")
	err := m.ensureGroup()
	if err != nil {
		return fmt.Errorf("failed to ensure group: %v", err)
	}
	m.logger.Debug("Network jail group ready", "groupID", m.groupID)

	// Setup PF rules
	m.logger.Debug("Setting up PF rules")
	err = m.setupPFRules()
	if err != nil {
		return fmt.Errorf("failed to setup PF rules: %v", err)
	}
	m.logger.Debug("PF rules setup completed")

	m.logger.Debug("Setup completed successfully")
	return nil
}

// Execute runs the command with the network jail group membership
func (m *MacOSNetJail) Command(command []string) *exec.Cmd {
	m.logger.Debug("Command called", "command", command)

	// Create command directly (no sg wrapper needed)
	m.logger.Debug("Creating command with group membership", "groupID", m.groupID)
	cmd := exec.Command(command[0], command[1:]...)
	m.logger.Debug("Full command args", "args", command)

	// Set up environment
	m.logger.Debug("Setting up environment")
	env := os.Environ()

	// Add extra environment variables from config
	for key, value := range m.config.Env {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}

	// When running under sudo, restore essential user environment variables
	sudoUser := os.Getenv("SUDO_USER")
	if sudoUser != "" {
		user, err := user.Lookup(sudoUser)
		if err == nil {
			// Set HOME to original user's home directory
			env = append(env, fmt.Sprintf("HOME=%s", user.HomeDir))
			// Set USER to original username
			env = append(env, fmt.Sprintf("USER=%s", sudoUser))
			// Set LOGNAME to original username (some tools check this instead of USER)
			env = append(env, fmt.Sprintf("LOGNAME=%s", sudoUser))
			m.logger.Debug("Restored user environment", "home", user.HomeDir, "user", sudoUser)
		}
	}

	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	// Set group ID using syscall
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Gid: uint32(m.groupID),
		},
	}

	// Drop privileges to original user if running under sudo
	sudoUID := os.Getenv("SUDO_UID")
	if sudoUID != "" {
		uid, err := strconv.Atoi(sudoUID)
		if err != nil {
			m.logger.Warn("Invalid SUDO_UID, subprocess will run as root", "sudo_uid", sudoUID, "error", err)
		} else {
			// Use original user ID but KEEP the jail group for network isolation
			cmd.SysProcAttr = &syscall.SysProcAttr{
				Credential: &syscall.Credential{
					Uid: uint32(uid),
					Gid: uint32(m.groupID), // Keep jail group, not original user's group
				},
			}
			m.logger.Debug("Dropping privileges to original user with jail group", "uid", uid, "jail_gid", m.groupID)
		}
	}

	return cmd
}

// Cleanup removes PF rules and cleans up temporary files
func (m *MacOSNetJail) Close() error {
	m.logger.Debug("Starting cleanup process")
	if m.config.SkipCleanup {
		m.logger.Debug("Skipping cleanup (SkipCleanup=true)")
		return nil
	}

	// Remove PF rules
	m.logger.Debug("Removing PF rules")
	err := m.removePFRules()
	if err != nil {
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
	output, err := exec.Command("dscl", ".", "-read", fmt.Sprintf("/Groups/%s", groupName), "PrimaryGroupID").Output()
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
	cmd := exec.Command("dseditgroup", "-o", "create", groupName)
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to create group: %v", err)
	}

	// Get the newly created group's GID
	output, err = exec.Command("dscl", ".", "-read", fmt.Sprintf("/Groups/%s", groupName), "PrimaryGroupID").Output()
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

	return fmt.Errorf("failed to get GID for group %s", groupName)
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
	err = os.WriteFile(m.pfRulesPath, []byte(rules), 0644)
	if err != nil {
		return fmt.Errorf("failed to write PF rules file: %v", err)
	}

	// Load rules into anchor
	cmd := exec.Command("pfctl", "-a", pfAnchorName, "-f", m.pfRulesPath)
	err = cmd.Run()
	if err != nil {
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
`, pfAnchorName, pfAnchorName)

	// Write and load the main ruleset
	err = os.WriteFile(m.mainRulesPath, []byte(mainRules), 0644)
	if err != nil {
		return fmt.Errorf("failed to write main PF rules: %v", err)
	}

	cmd = exec.Command("pfctl", "-f", m.mainRulesPath)
	err = cmd.Run()
	if err != nil {
		// Don't fail if main rules can't be loaded, but warn
		fmt.Fprintf(os.Stderr, "Warning: failed to load main PF rules: %v\n", err)
	}

	// Verify that rules were loaded correctly
	cmd = exec.Command("pfctl", "-a", pfAnchorName, "-s", "rules")
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
	cmd := exec.Command("pfctl", "-a", pfAnchorName, "-F", "all")
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