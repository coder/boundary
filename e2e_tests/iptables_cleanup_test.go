package e2e_tests

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/coder/boundary/e2e_tests/util"
	"github.com/stretchr/testify/require"
)

const (
	filterTable = "filter"
	natTable    = "nat"
)

func getIptablesRules(tableName string) (string, error) {
	cmd := exec.Command("sudo", "iptables", "-L", "-n", "-t", tableName)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get iptables rules: %v", err)
	}
	rules := string(output)

	return rules, nil
}

func TestIPTablesCleanup(t *testing.T) {
	// Step 1: Capture initial iptables rules
	initialFilterRules, err := getIptablesRules(filterTable)
	require.NoError(t, err)
	initialNatRules, err := getIptablesRules(natTable)
	require.NoError(t, err)

	// Step 2: Run Boundary
	// Find project root by looking for go.mod file
	projectRoot := util.FindProjectRoot(t)

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
	filterRules, err := getIptablesRules(filterTable)
	require.NoError(t, err)
	natRules, err := getIptablesRules(natTable)
	require.NoError(t, err)

	require.Equal(t, initialFilterRules, filterRules)
	require.Equal(t, initialNatRules, natRules)
}
