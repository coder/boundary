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
	buildCmd := exec.Command("go", "build", "-o", path.Join(dir, "boundary-test"))
	buildCmd.Dir = "../cmd/boundary"
	err := buildCmd.Run()
	if err != nil {
		panic(fmt.Sprintf("Failed to build boundary binary: %v", err))
	}
}
