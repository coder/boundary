//go:build darwin

package jail

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	prefix = "coder_boundary"
)

func newNamespaceName() string {
	return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano()%10000000)
}

const (
	pfAnchorName = "coder_boundary"
	groupName    = "coder_boundary"
)

// MacOSJail implements network boundary using macOS PF (Packet Filter) and group-based isolation
type MacOSJail struct {
	restrictedGid int
	pfRulesPath   string
	mainRulesPath string
	logger        *slog.Logger
	commandEnv    []string
	procAttr      *syscall.SysProcAttr
	httpProxyPort int
	configDir     string
	caCertPath    string
	homeDir       string
	username      string
	uid           int
	gid           int
}

// NewMacOSJail creates a new macOS network boundary instance
func NewMacOSJail(config Config) (*MacOSJail, error) {
	ns := newNamespaceName()
	pfRulesPath := fmt.Sprintf("/tmp/%s.pf", ns)
	mainRulesPath := fmt.Sprintf("/tmp/%s_main.pf", ns)

	return &MacOSJail{
		pfRulesPath:   pfRulesPath,
		mainRulesPath: mainRulesPath,
		logger:        config.Logger,
		httpProxyPort: config.HttpProxyPort,
		configDir:     config.ConfigDir,
		caCertPath:    config.CACertPath,
		homeDir:       config.HomeDir,
		username:      config.Username,
		uid:           config.Uid,
		gid:           config.Gid,
	}, nil
}

func SetupChildNetworking(vethNetJail string) error {
	return nil
}

// Setup creates the network boundary group and configures PF rules
func (n *MacOSJail) ConfigureBeforeCommandExecution() error {
	n.logger.Debug("Setup called")

	// Create or get network boundary group
	n.logger.Debug("Creating or ensuring network boundary group")
	err := n.ensureGroup()
	if err != nil {
		return fmt.Errorf("failed to ensure group: %v", err)
	}

	// Setup PF rules
	n.logger.Debug("Setting up PF rules")
	err = n.setupPFRules()
	if err != nil {
		return fmt.Errorf("failed to setup PF rules: %v", err)
	}

	// Prepare environment once during setup
	n.logger.Debug("Preparing environment")

	e := getEnvs(n.configDir, n.caCertPath)
	n.commandEnv = mergeEnvs(e, map[string]string{
		"HOME":    n.homeDir,
		"USER":    n.username,
		"LOGNAME": n.username,
	})

	// Prepare process credentials once during setup
	n.logger.Debug("Preparing process credentials")
	// Use original user ID but KEEP the boundary group for network isolation
	procAttr := &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: uint32(n.uid),
			Gid: uint32(n.restrictedGid),
		},
	}

	// Store prepared process attributes for use in Command method
	n.procAttr = procAttr

	n.logger.Debug("Setup completed successfully")
	return nil
}

// Command runs the command with the network boundary group membership
func (n *MacOSJail) Command(command []string) *exec.Cmd {
	n.logger.Debug("Command called", "command", command)

	// Create command directly (no sg wrapper needed)
	n.logger.Debug("Creating command with group membership", "groupID", n.restrictedGid)
	cmd := exec.Command(command[0], command[1:]...)
	n.logger.Debug("Full command args", "args", command)

	cmd.Env = n.commandEnv

	// Use prepared process attributes from Open method
	cmd.SysProcAttr = n.procAttr

	return cmd
}

// Cleanup removes PF rules and cleans up temporary files
func (n *MacOSJail) Close() error {
	n.logger.Debug("Starting cleanup process")

	// Remove PF rules
	n.logger.Debug("Removing PF rules")
	err := n.removePFRules()
	if err != nil {
		return fmt.Errorf("failed to remove PF rules: %v", err)
	}

	// Clean up temporary files
	n.logger.Debug("Cleaning up temporary files")
	n.cleanupTempFiles()

	n.logger.Debug("Cleanup completed successfully")
	return nil
}

// ensureGroup creates the network boundary group if it doesn't exist
func (n *MacOSJail) ensureGroup() error {
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
					n.restrictedGid = gid
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
				n.restrictedGid = gid
				return nil
			}
		}
	}

	return fmt.Errorf("failed to get GID for group %s", groupName)
}

// getDefaultInterface gets the default network interface
func (n *MacOSJail) getDefaultInterface() (string, error) {
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

// createPFRules creates PF rules for comprehensive TCP traffic diversion
func (n *MacOSJail) createPFRules() (string, error) {
	// Get the default network interface
	iface, err := n.getDefaultInterface()
	if err != nil {
		return "", fmt.Errorf("failed to get default interface: %v", err)
	}

	// Create comprehensive PF rules for ALL TCP traffic interception
	// This prevents bypass via non-standard ports (8080, 3306, 22, etc.)
	rules := fmt.Sprintf(`# comprehensive TCP boundarying PF rules for GID %d on interface %s
# COMPREHENSIVE APPROACH: Intercept ALL TCP traffic from the boundaryed group
# This ensures NO TCP traffic can bypass the proxy by using alternative ports

# First, redirect ALL TCP traffic arriving on lo0 to our HTTP proxy with TLS termination
# The HTTP proxy with TLS termination can handle both HTTP and HTTPS traffic
rdr pass on lo0 inet proto tcp from any to any -> 127.0.0.1 port %d

# Route ALL TCP traffic from boundary group to lo0 where it will be redirected
pass out route-to (lo0 127.0.0.1) inet proto tcp from any to any group %d keep state

# Also handle ALL TCP traffic on the specific interface from the group
pass out on %s route-to (lo0 127.0.0.1) inet proto tcp from any to any group %d keep state

# Allow all loopback traffic
pass on lo0 all
`,
		n.restrictedGid,
		iface,
		n.httpProxyPort, // Use HTTP proxy with TLS termination for all TCP traffic
		n.restrictedGid,
		iface,
		n.restrictedGid,
	)

	n.logger.Debug("Comprehensive TCP boundarying enabled for macOS", "group_id", n.restrictedGid, "proxy_port", n.httpProxyPort)
	return rules, nil
}

// setupPFRules configures packet filter rules to redirect traffic
func (n *MacOSJail) setupPFRules() error {
	// Create PF rules
	rules, err := n.createPFRules()
	if err != nil {
		return fmt.Errorf("failed to create PF rules: %v", err)
	}

	// Write rules to temp file
	err = os.WriteFile(n.pfRulesPath, []byte(rules), 0644)
	if err != nil {
		return fmt.Errorf("failed to write PF rules file: %v", err)
	}

	// Load rules into anchor
	cmd := exec.Command("pfctl", "-a", pfAnchorName, "-f", n.pfRulesPath)
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to load PF rules: %v", err)
	}

	// Enable PF if not already enabled
	cmd = exec.Command("pfctl", "-E")
	_ = cmd.Run() // Ignore error as PF might already be enabled

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
	err = os.WriteFile(n.mainRulesPath, []byte(mainRules), 0644)
	if err != nil {
		return fmt.Errorf("failed to write main PF rules: %v", err)
	}

	cmd = exec.Command("pfctl", "-f", n.mainRulesPath)
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
func (n *MacOSJail) removePFRules() error {
	// Flush the anchor
	cmd := exec.Command("pfctl", "-a", pfAnchorName, "-F", "all")
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to flush PF anchor: %v", err)
	}

	return nil
}

// cleanupTempFiles removes temporary rule files
func (n *MacOSJail) cleanupTempFiles() {
	if n.pfRulesPath != "" {
		err := os.Remove(n.pfRulesPath)
		if err != nil {
			n.logger.Error("Failed to remove temporary PF rules file", "file", n.pfRulesPath, "error", err)
		}
	}
	if n.mainRulesPath != "" {
		err := os.Remove(n.mainRulesPath)
		if err != nil {
			n.logger.Error("Failed to remove temporary main PF rules file", "file", n.mainRulesPath, "error", err)
		}
	}
}

func (u *MacOSJail) ConfigureAfterCommandExecution(processPID int) error {
	return nil
}
