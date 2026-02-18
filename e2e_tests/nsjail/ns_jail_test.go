package nsjail

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/coder/boundary/config"
	"github.com/stretchr/testify/require"
)

func TestNamespaceJail(t *testing.T) {
	// Create and configure nsjail test
	nt := NewNSJailTest(t,
		WithNSJailAllowedDomain("dev.coder.com"),
		WithNSJailAllowedDomain("jsonplaceholder.typicode.com"),
		WithNSJailLogLevel("debug"),
	).
		Build().
		Start()

	// Ensure cleanup
	defer nt.Stop()

	// Test allowed HTTP request
	t.Run("HTTPRequestThroughBoundary", func(t *testing.T) {
		expectedResponse := `{
  "userId": 1,
  "id": 1,
  "title": "delectus aut autem",
  "completed": false
}`
		nt.ExpectAllowed("http://jsonplaceholder.typicode.com/todos/1", expectedResponse)
	})

	// Test allowed HTTPS request
	t.Run("HTTPSRequestThroughBoundary", func(t *testing.T) {
		expectedResponse := `{"message":"👋"}
`
		nt.ExpectAllowed("https://dev.coder.com/api/v2", expectedResponse)
	})

	// Test blocked HTTP request
	t.Run("HTTPBlockedDomainTest", func(t *testing.T) {
		nt.ExpectDeny("http://example.com")
	})

	// Test blocked HTTPS request
	t.Run("HTTPSBlockedDomainTest", func(t *testing.T) {
		nt.ExpectDeny("https://example.com")
	})
}

// TestNamespaceJailNoUserNamespace runs boundary with --no-user-namespace and verifies
// that the jail still works (network isolation, allow/deny). Used for environments that
// disallow user namespaces (e.g. Bottlerocket).
func TestNamespaceJailNoUserNamespace(t *testing.T) {
	nt := NewNSJailTest(t,
		WithNSJailAllowedDomain("jsonplaceholder.typicode.com"),
		WithNSJailNoUserNamespace(),
		WithNSJailLogLevel("debug"),
	).
		Build().
		Start()

	defer nt.Stop()

	t.Run("AllowedHTTPWithNoUserNS", func(t *testing.T) {
		expected := `{
  "userId": 1,
  "id": 1,
  "title": "delectus aut autem",
  "completed": false
}`
		nt.ExpectAllowed("http://jsonplaceholder.typicode.com/todos/1", expected)
	})

	t.Run("DeniedHTTPWithNoUserNS", func(t *testing.T) {
		nt.ExpectDeny("http://example.com")
	})
}

func TestUDPBlocking(t *testing.T) {
	// Create and configure nsjail test
	nt := NewNSJailTest(t,
		WithNSJailAllowedDomain("dev.coder.com"),
		WithNSJailLogLevel("debug"),
	).
		Build().
		Start()

	// Ensure cleanup
	defer nt.Stop()

	// Test that UDP to non-DNS port is blocked
	t.Run("UDPBlocked", func(t *testing.T) {
		// Start UDP server on host (listening on 0.0.0.0:9999)
		serverCmd := exec.Command("nc", "-u", "-l", "0.0.0.0", "9999")
		serverOutput := &bytes.Buffer{}
		serverCmd.Stdout = serverOutput
		serverCmd.Stderr = serverOutput

		err := serverCmd.Start()
		require.NoError(t, err, "Failed to start UDP server")
		defer func() {
			if err := serverCmd.Process.Kill(); err != nil {
				t.Logf("Failed to kill UDP server: %v", err)
			}
			// Wait() may return an error if process was killed (expected), so we ignore it
			_ = serverCmd.Wait()
		}()

		// Give server time to start
		time.Sleep(500 * time.Millisecond)

		// Try to send UDP from namespace to host (192.168.100.1 is the host's veth IP)
		// nc will exit with error if it can't send/receive, which is expected when UDP is blocked
		// We don't check the error - we check if server received anything
		_ = nt.sendUDP("192.168.100.1", 9999, "test message")

		// Give time for packet to arrive (if it wasn't blocked)
		time.Sleep(500 * time.Millisecond)

		// Kill server and check output
		if err := serverCmd.Process.Kill(); err != nil {
			t.Logf("Failed to kill UDP server: %v", err)
		}
		// Wait() may return an error if process was killed (expected), so we ignore it
		_ = serverCmd.Wait()

		// If UDP is blocked, server should receive nothing
		output := serverOutput.String()
		require.Empty(t, output, "UDP packet should be blocked, but server received: %s", output)
	})

	// Test that DNS still works (UDP port 53)
	t.Run("DNSStillWorks", func(t *testing.T) {
		pid := fmt.Sprintf("%v", nt.pid)
		userInfo := config.GetUserInfo()

		args := []string{"nsenter", "-t", pid, "-n", "--",
			"env", fmt.Sprintf("SSL_CERT_FILE=%v", userInfo.CACertPath()), "dig", "+short", "example.com"}

		digCmd := exec.Command("sudo", args...)
		output, err := digCmd.Output()
		require.NoError(t, err, "DNS lookup should work")

		// Should return dummy DNS IP
		result := strings.TrimSpace(string(output))
		require.Equal(t, "6.6.6.6", result, "DNS should return dummy IP")
	})
}
