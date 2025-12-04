package e2e_tests

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"testing"
)

func TestMain(m *testing.M) {
	// The binary is compiled once for all tests and shared between them to avoid
	// recompiling it for each test.
	buildBinary()
	code := m.Run()
	os.Exit(code)
}

func buildBinary() {
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Dir(file)
	binaryPath := path.Join(dir, "boundary-test")

	buildCmd := exec.Command("go", "build", "-o", binaryPath)
	buildCmd.Dir = "../cmd/boundary"
	err := buildCmd.Run()
	if err != nil {
		panic(fmt.Sprintf("Failed to build boundary binary: %v", err))
	}

	// Ensure the binary has execute permissions
	err = os.Chmod(binaryPath, 0755)
	if err != nil {
		panic(fmt.Sprintf("Failed to set execute permissions on boundary binary: %v", err))
	}

	// Set capabilities on the binary so it can create network namespaces and configure networking
	// without needing sudo. This allows boundary to use user namespaces (CLONE_NEWUSER) properly.
	setcapCmd := exec.Command("sudo", "setcap", "cap_net_admin+ep", binaryPath)
	output, err := setcapCmd.CombinedOutput()
	if err != nil {
		panic(fmt.Sprintf("Failed to set capabilities on boundary binary: %v, output: %s", err, output))
	}
}
