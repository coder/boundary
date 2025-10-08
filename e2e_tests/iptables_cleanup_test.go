package e2e_tests

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestIPTablesCleanup(t *testing.T) {
	// Step 1: Capture initial iptables rules
	initialCmd := exec.Command("sudo", "iptables", "-L", "-n")
	initialOutput, err := initialCmd.Output()
	require.NoError(t, err, "Failed to get initial iptables rules")
	initialRules := string(initialOutput)
	//fmt.Printf("Initial iptables rules:\n%s", initialRules)

	// Step 2: Run Boundary
	// Find project root by looking for go.mod file
	projectRoot := findProjectRoot(t)

	// Build the boundary binary
	buildCmd := exec.Command("go", "build", "-o", "/tmp/boundary-test", "./cmd/...")
	buildCmd.Dir = projectRoot
	err = buildCmd.Run()
	require.NoError(t, err, "Failed to build boundary binary")

	// Create context for boundary process
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start boundary process with sudo
	boundaryCmd := exec.CommandContext(ctx, "/tmp/boundary-test",
		"--allow", "dev.coder.com",
		"--allow", "jsonplaceholder.typicode.com",
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

	// Gracefully close process, call cleanup methods
	err = boundaryCmd.Process.Signal(os.Interrupt)
	require.NoError(t, err, "Failed to interrupt boundary process")
	time.Sleep(time.Second * 1)

	// Step 3: Clean up
	cancel()                 // This will terminate the boundary process
	err = boundaryCmd.Wait() // Wait for process to finish
	if err != nil {
		t.Logf("Boundary process finished with error: %v", err)
	}

	// Clean up binary
	err = os.Remove("/tmp/boundary-test")
	require.NoError(t, err, "Failed to remove /tmp/boundary-test")

	// Step 4: Capture iptables rules after boundary has executed
	iptablesCmd := exec.Command("sudo", "iptables", "-L", "-n")
	iptablesOutput, err := iptablesCmd.Output()
	require.NoError(t, err, "Failed to get iptables rules")
	iptablesRules := string(iptablesOutput)

	require.Equal(t, initialRules, iptablesRules)
}
