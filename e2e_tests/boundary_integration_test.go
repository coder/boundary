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

func getChildProcessPID(t *testing.T) int {
	cmd := exec.Command("pgrep", "-f", "boundary-test", "-n")
	output, err := cmd.Output()
	require.NoError(t, err)

	pidStr := strings.TrimSpace(string(output))
	pid, err := strconv.Atoi(pidStr)
	require.NoError(t, err)
	return pid
}

// This test runs boundary process with such allowed domains:
// - dev.coder.com
// - jsonplaceholder.typicode.com
// It makes sure you can access these domains with curl tool (using both HTTP and HTTPS protocols).
// Then it makes sure you can NOT access example.com domain which is not allowed (using both HTTP and HTTPS protocols).
func TestBoundaryIntegration(t *testing.T) {
	// Find project root by looking for go.mod file
	projectRoot := findProjectRoot(t)

	// Build the boundary binary
	buildCmd := exec.Command("go", "build", "-o", "/tmp/boundary-test", "./cmd/...")
	buildCmd.Dir = projectRoot
	err := buildCmd.Run()
	require.NoError(t, err, "Failed to build boundary binary")

	// Create context for boundary process
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start boundary process with sudo
	boundaryCmd := exec.CommandContext(ctx, "/tmp/boundary-test",
		"--allow", "domain=dev.coder.com",
		"--allow", "domain=jsonplaceholder.typicode.com",
		"--log-level", "debug",
		"--", "/bin/bash", "-c", "/usr/bin/sleep 10 && /usr/bin/echo 'Test completed'")

	boundaryCmd.Stdin = os.Stdin
	boundaryCmd.Stdout = os.Stdout
	boundaryCmd.Stderr = os.Stderr

	// Start the process
	err = boundaryCmd.Start()
	require.NoError(t, err, "Failed to start boundary process")

	// Give boundary time to start
	time.Sleep(2 * time.Second)

	pidInt := getChildProcessPID(t)
	pid := fmt.Sprintf("%v", pidInt)

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
	t.Run("HTTPBlockedDomainTest", func(t *testing.T) {
		// Run curl directly in the namespace using ip netns exec
		curlCmd := exec.Command("sudo", "nsenter", "-t", pid, "-n", "--",
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

	// Test blocked domain (from inside the jail)
	t.Run("HTTPSBlockedDomainTest", func(t *testing.T) {
		_, _, _, _, configDir := util.GetUserInfo()
		certPath := fmt.Sprintf("%v/ca-cert.pem", configDir)

		// Run curl directly in the namespace using ip netns exec
		curlCmd := exec.Command("sudo", "nsenter", "-t", pid, "-n", "--",
			"env", fmt.Sprintf("SSL_CERT_FILE=%v", certPath), "curl", "-s", "https://example.com")

		// Capture stderr separately
		var stderr bytes.Buffer
		curlCmd.Stderr = &stderr
		output, err := curlCmd.Output()

		if err != nil {
			t.Fatalf("curl command failed: %v, stderr: %s, output: %s", err, stderr.String(), string(output))
		}
		require.Contains(t, string(output), "Request Blocked by Boundary")
	})

	// Gracefully close process, call cleanup methods
	err = boundaryCmd.Process.Signal(os.Interrupt)
	require.NoError(t, err, "Failed to interrupt boundary process")
	time.Sleep(time.Second * 1)

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

// This test runs boundary process with such allowed domains:
// - example.com
// It makes sure you can access this domain with curl tool (using both HTTP and HTTPS protocols).
// It indirectly tests that ContentLength header is properly set, otherwise it fails.
func TestContentLengthHeader(t *testing.T) {
	expectedResponse := `<!doctype html><html lang="en"><head><title>Example Domain</title><meta name="viewport" content="width=device-width, initial-scale=1"><style>body{background:#eee;width:60vw;margin:15vh auto;font-family:system-ui,sans-serif}h1{font-size:1.5em}div{opacity:0.8}a:link,a:visited{color:#348}</style><body><div><h1>Example Domain</h1><p>This domain is for use in documentation examples without needing permission. Avoid use in operations.<p><a href="https://iana.org/domains/example">Learn more</a></div></body></html>
`

	// Find project root by looking for go.mod file
	projectRoot := findProjectRoot(t)

	// Build the boundary binary
	buildCmd := exec.Command("go", "build", "-o", "/tmp/boundary-test", "./cmd/...")
	buildCmd.Dir = projectRoot
	err := buildCmd.Run()
	require.NoError(t, err, "Failed to build boundary binary")

	// Create context for boundary process
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start boundary process with sudo
	boundaryCmd := exec.CommandContext(ctx, "/tmp/boundary-test",
		"--allow", "example.com",
		"--log-level", "debug",
		"--", "/bin/bash", "-c", "/usr/bin/sleep 10 && /usr/bin/echo 'Test completed'")

	boundaryCmd.Stdin = os.Stdin
	boundaryCmd.Stdout = os.Stdout
	boundaryCmd.Stderr = os.Stderr

	// Start the process
	err = boundaryCmd.Start()
	require.NoError(t, err, "Failed to start boundary process")

	// Give boundary time to start
	time.Sleep(2 * time.Second)

	pidInt := getChildProcessPID(t)
	pid := fmt.Sprintf("%v", pidInt)

	// Test HTTP request through boundary (from inside the jail)
	t.Run("HTTPRequestThroughBoundary", func(t *testing.T) {
		// Run curl directly in the namespace using ip netns exec
		curlCmd := exec.Command("sudo", "nsenter", "-t", pid, "-n", "--",
			"curl", "http://example.com")

		// Capture stderr separately
		var stderr bytes.Buffer
		curlCmd.Stderr = &stderr
		output, err := curlCmd.Output()

		if err != nil {
			t.Fatalf("curl command failed: %v, stderr: %s, output: %s", err, stderr.String(), string(output))
		}

		// Verify response contains expected content
		require.Equal(t, expectedResponse, string(output))
	})

	// Test HTTPS request through boundary (from inside the jail)
	t.Run("HTTPSRequestThroughBoundary", func(t *testing.T) {
		_, _, _, _, configDir := util.GetUserInfo()
		certPath := fmt.Sprintf("%v/ca-cert.pem", configDir)

		// Run curl directly in the namespace using ip netns exec
		curlCmd := exec.Command("sudo", "nsenter", "-t", pid, "-n", "--",
			"env", fmt.Sprintf("SSL_CERT_FILE=%v", certPath), "curl", "-s", "https://example.com")

		// Capture stderr separately
		var stderr bytes.Buffer
		curlCmd.Stderr = &stderr
		output, err := curlCmd.Output()

		if err != nil {
			t.Fatalf("curl command failed: %v, stderr: %s, output: %s", err, stderr.String(), string(output))
		}

		// Verify response contains expected content
		require.Equal(t, expectedResponse, string(output))
	})

	// Gracefully close process, call cleanup methods
	err = boundaryCmd.Process.Signal(os.Interrupt)
	require.NoError(t, err, "Failed to interrupt boundary process")
	time.Sleep(time.Second * 1)

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
