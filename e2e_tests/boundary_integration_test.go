package e2e_tests

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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

//func getChildProcessPID(t *testing.T) int {
//	// Option 1: Look for processes with CHILD=true
//	cmd := exec.Command("pgrep", "-f", "CHILD=true")
//	output, err := cmd.CombinedOutput()
//	require.NoError(t, err, "output: %v", output)
//
//	pidStr := strings.TrimSpace(string(output))
//	pid, err := strconv.Atoi(pidStr)
//	require.NoError(t, err)
//	return pid
//
//	// Option 2: Use the boundary process's child PID
//	// This would require modifying boundary to expose the child PID
//}

//func getBoundaryProcessPID(t *testing.T) int {
//	cmd := exec.Command("pgrep", "-f", "boundary-test")
//	output, err := cmd.Output()
//	require.NoError(t, err)
//
//	pidStr := strings.TrimSpace(string(output))
//	pid, err := strconv.Atoi(pidStr)
//	require.NoError(t, err)
//	return pid
//}
//
//func getChildProcessPID(t *testing.T) int {
//	boundaryPID := getBoundaryProcessPID(t)
//
//	cmd := exec.Command("pgrep", "-P", fmt.Sprintf("%d", boundaryPID))
//	output, err := cmd.Output()
//	require.NoError(t, err)
//
//	pidStr := strings.TrimSpace(string(output))
//	pid, err := strconv.Atoi(pidStr)
//	require.NoError(t, err)
//	return pid
//}

func getChildProcessPID(t *testing.T) int {
	cmd := exec.Command("pgrep", "-f", "boundary-test", "-n")
	output, err := cmd.Output()
	require.NoError(t, err)

	pidStr := strings.TrimSpace(string(output))
	pid, err := strconv.Atoi(pidStr)
	require.NoError(t, err)
	return pid
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
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Second)
	defer cancel()

	// Start boundary process with sudo
	boundaryCmd := exec.CommandContext(ctx, "/tmp/boundary-test",
		"--allow", "dev.coder.com",
		"--allow", "jsonplaceholder.typicode.com",
		"--log-level", "debug",
		//"--", "/bin/bash")
		"--", "/bin/bash", "-c", "/usr/bin/sleep 21 && /usr/bin/echo 'Test completed'")

	boundaryCmd.Stdin = os.Stdin
	boundaryCmd.Stdout = os.Stdout
	boundaryCmd.Stderr = os.Stderr

	// Start the process
	err = boundaryCmd.Start()
	require.NoError(t, err, "Failed to start boundary process")

	// Give boundary time to start
	time.Sleep(2 * time.Second)

	// Get the namespace name that boundary created
	//namespaceName := getNamespaceName(t)

	pidInt := getChildProcessPID(t)
	pid := fmt.Sprintf("%v", pidInt)

	fmt.Printf("pidInt: %v\n", pidInt)
	//time.Sleep(200 * time.Second)

	// Test HTTP request through boundary (from inside the jail)
	t.Run("HTTPRequestThroughBoundary", func(t *testing.T) {
		// Run curl directly in the namespace using ip netns exec
		curlCmd := exec.Command("sudo", "nsenter", "-t", pid, "-n", "--",
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
		curlCmd := exec.Command("sudo", "sudo", "nsenter", "-t", pid, "-n", "--",
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
		curlCmd := exec.Command("sudo", "sudo", "nsenter", "-t", pid, "-n", "--",
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
