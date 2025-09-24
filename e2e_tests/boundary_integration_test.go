package e2e_tests

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/boundary/util"
	"github.com/stretchr/testify/require"
)

// findProjectRoot finds the project root by looking for go.mod file
func findProjectRoot(t *testing.T) string {
	cwd, err := os.Getwd()
	require.NoError(t, err, "Failed to get current working directory")

	// Start from current directory and walk up until we find go.mod
	dir := cwd
	for {
		goModPath := filepath.Join(dir, "go.mod")
		if _, err := os.Stat(goModPath); err == nil {
			return dir
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached filesystem root
			t.Fatalf("Could not find go.mod file starting from %s", cwd)
		}
		dir = parent
	}
}

// getNamespaceName gets the single network namespace name
// Fails if there are 0 or multiple namespaces
func getNamespaceName(t *testing.T) string {
	cmd := exec.Command("ip", "netns", "list")
	output, err := cmd.Output()
	require.NoError(t, err, "Failed to list network namespaces")

	lines := strings.Split(string(output), "\n")
	var namespaces []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			// Extract namespace name (first field)
			parts := strings.Fields(line)
			if len(parts) > 0 {
				namespaces = append(namespaces, parts[0])
			}
		}
	}

	require.Len(t, namespaces, 1, "Expected exactly one network namespace, found %d: %v", len(namespaces), namespaces)
	return namespaces[0]
}

func TestBoundaryIntegration(t *testing.T) {
	// Find project root by looking for go.mod file
	projectRoot := findProjectRoot(t)

	// Build the boundary binary
	buildCmd := exec.Command("go", "build", "-o", "/tmp/boundary-test", "./cmd/...")
	buildCmd.Dir = projectRoot
	err := buildCmd.Run()
	require.NoError(t, err, "Failed to build boundary binary")

	// Create context for boundary process
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Start boundary process with sudo
	boundaryCmd := exec.CommandContext(ctx, "/tmp/boundary-test",
		"--allow", "dev.coder.com",
		"--allow", "jsonplaceholder.typicode.com",
		"--log-level", "debug",
		"--", "bash", "-c", "sleep 10 && echo 'Test completed'")

	// Suppress output to prevent terminal corruption
	boundaryCmd.Stdout = os.Stdout // Let it go to /dev/null
	boundaryCmd.Stderr = os.Stderr

	// Start the process
	err = boundaryCmd.Start()
	require.NoError(t, err, "Failed to start boundary process")

	// Give boundary time to start
	time.Sleep(2 * time.Second)

	// Get the namespace name that boundary created
	namespaceName := getNamespaceName(t)

	// Test HTTP request through boundary (from inside the jail)
	t.Run("HTTPRequestThroughBoundary", func(t *testing.T) {
		// Run curl directly in the namespace using ip netns exec
		curlCmd := exec.Command("sudo", "ip", "netns", "exec", namespaceName,
			"curl", "http://jsonplaceholder.typicode.com/todos/1")

		// Capture stderr separately
		var stderr bytes.Buffer
		curlCmd.Stderr = &stderr
		output, err := curlCmd.Output()

		if err != nil {
			t.Fatalf("curl command failed: %v, stderr: %s, output: %s", err, stderr.String(), string(output))
		}

		// Verify response contains expected content
		expectedResponse := `{
  "userId": 1,
  "id": 1,
  "title": "delectus aut autem",
  "completed": false
}`
		require.Equal(t, expectedResponse, string(output))
	})

	// Test HTTPS request through boundary (from inside the jail)
	t.Run("HTTPSRequestThroughBoundary", func(t *testing.T) {
		_, _, _, _, configDir := util.GetUserInfo()
		certPath := fmt.Sprintf("%v/ca-cert.pem", configDir)

		// Run curl directly in the namespace using ip netns exec
		curlCmd := exec.Command("sudo", "ip", "netns", "exec", namespaceName,
			"env", fmt.Sprintf("SSL_CERT_FILE=%v", certPath), "curl", "-s", "https://dev.coder.com/api/v2")

		// Capture stderr separately
		var stderr bytes.Buffer
		curlCmd.Stderr = &stderr
		output, err := curlCmd.Output()

		if err != nil {
			t.Fatalf("curl command failed: %v, stderr: %s, output: %s", err, stderr.String(), string(output))
		}

		// Verify response contains expected content
		expectedResponse := `{"message":"👋"}
`
		require.Equal(t, expectedResponse, string(output))
	})

	// Test blocked domain (from inside the jail)
	t.Run("BlockedDomainTest", func(t *testing.T) {
		// Run curl directly in the namespace using ip netns exec
		curlCmd := exec.Command("sudo", "ip", "netns", "exec", namespaceName,
			"curl", "-s", "http://example.com")

		// Capture stderr separately
		var stderr bytes.Buffer
		curlCmd.Stderr = &stderr
		output, err := curlCmd.Output()

		if err != nil {
			t.Fatalf("curl command failed: %v, stderr: %s, output: %s", err, stderr.String(), string(output))
		}
		require.Contains(t, string(output), "Request Blocked by Boundary")
	})

	// Clean up
	cancel()                 // This will terminate the boundary process
	err = boundaryCmd.Wait() // Wait for process to finish
	if err != nil {
		t.Logf("Boundary process finished with error: %v", err)
	}

	// Clean up binary
	err = os.Remove("/tmp/boundary-test")
	require.NoError(t, err, "Failed to remove /tmp/boundary-test")
}

func TestIptablesCleanup(t *testing.T) {
	// Step 1: Capture initial iptables rules
	t.Log("Step 1: Capturing initial iptables rules...")
	initialCmd := exec.Command("sudo", "iptables", "-L", "-n", "-v")
	initialOutput, err := initialCmd.Output()
	require.NoError(t, err, "Failed to get initial iptables rules")
	initialRules := string(initialOutput)
	t.Logf("Initial iptables rules:\n%s", initialRules)

	// Step 2: Create and start LinuxJail
	t.Log("Step 2: Creating and starting LinuxJail...")
	
	// Import the jail package to create LinuxJail directly
	// We'll need to create a minimal config
	config := struct {
		Logger        interface{}
		HttpProxyPort int
		ConfigDir     string
		CACertPath    string
		HomeDir       string
		Username      string
		Uid           int
		Gid           int
	}{
		HttpProxyPort: 8080,
		ConfigDir:     "/tmp/test-config",
		CACertPath:    "/tmp/test-ca.pem",
		HomeDir:       "/tmp/test-home",
		Username:      "testuser",
		Uid:           1000,
		Gid:           1000,
	}

	// Create a temporary CA cert file for the test
	err = os.MkdirAll(config.ConfigDir, 0755)
	require.NoError(t, err, "Failed to create config directory")
	
	// Create a dummy CA cert file
	err = os.WriteFile(config.CACertPath, []byte("dummy cert"), 0644)
	require.NoError(t, err, "Failed to create dummy CA cert")

	// We'll use the boundary binary approach since we can't easily import jail package
	// Build the boundary binary
	projectRoot := findProjectRoot(t)
	buildCmd := exec.Command("go", "build", "-o", "/tmp/boundary-iptables-test", "./cmd/...")
	buildCmd.Dir = projectRoot
	err = buildCmd.Run()
	require.NoError(t, err, "Failed to build boundary binary for iptables test")

	// Create context for boundary process
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Start boundary process (this will create LinuxJail and setup iptables)
	boundaryCmd := exec.CommandContext(ctx, "/tmp/boundary-iptables-test",
		"--allow", "example.com",
		"--log-level", "debug",
		"--", "bash", "-c", "sleep 5 && echo 'Test completed'")

	boundaryCmd.Stdout = os.Stdout
	boundaryCmd.Stderr = os.Stderr

	// Start the process
	err = boundaryCmd.Start()
	require.NoError(t, err, "Failed to start boundary process for iptables test")

	// Give boundary time to start and setup iptables
	time.Sleep(2 * time.Second)

	// Step 3: Capture iptables rules after LinuxJail setup
	t.Log("Step 3: Capturing iptables rules after LinuxJail setup...")
	afterSetupCmd := exec.Command("sudo", "iptables", "-L", "-n", "-v")
	afterSetupOutput, err := afterSetupCmd.Output()
	require.NoError(t, err, "Failed to get iptables rules after setup")
	afterSetupRules := string(afterSetupOutput)
	t.Logf("Iptables rules after setup:\n%s", afterSetupRules)

	// Verify that new rules were added
	require.NotEqual(t, initialRules, afterSetupRules, "Iptables rules should have changed after LinuxJail setup")

	// Step 4: Stop boundary process (this should trigger cleanup)
	t.Log("Step 4: Stopping boundary process to trigger cleanup...")
	cancel() // This will terminate the boundary process
	err = boundaryCmd.Wait()
	if err != nil {
		t.Logf("Boundary process finished with error (expected): %v", err)
	}

	// Give cleanup time to complete
	time.Sleep(2 * time.Second)

	// Step 5: Capture iptables rules after cleanup
	t.Log("Step 5: Capturing iptables rules after cleanup...")
	afterCleanupCmd := exec.Command("sudo", "iptables", "-L", "-n", "-v")
	afterCleanupOutput, err := afterCleanupCmd.Output()
	require.NoError(t, err, "Failed to get iptables rules after cleanup")
	afterCleanupRules := string(afterCleanupOutput)
	t.Logf("Iptables rules after cleanup:\n%s", afterCleanupRules)

	// Step 6: Verify rules are identical to initial state
	t.Log("Step 6: Verifying iptables rules are cleaned up...")
	require.Equal(t, initialRules, afterCleanupRules, 
		"Iptables rules should be identical to initial state after cleanup.\n"+
		"Initial rules:\n%s\n\nAfter cleanup:\n%s", initialRules, afterCleanupRules)

	// Clean up
	err = os.Remove("/tmp/boundary-iptables-test")
	require.NoError(t, err, "Failed to remove test binary")
	
	err = os.RemoveAll(config.ConfigDir)
	require.NoError(t, err, "Failed to remove config directory")
	
	err = os.Remove(config.CACertPath)
	require.NoError(t, err, "Failed to remove dummy CA cert")

	t.Log("✓ Iptables cleanup test completed successfully")
}
