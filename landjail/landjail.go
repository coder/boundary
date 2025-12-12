package landjail

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"syscall"

	"github.com/landlock-lsm/go-landlock/landlock"
)

type Config struct {
	//BindTCPPorts    []int
	ConnectTCPPorts []int
}

func Apply(cfg Config) error {
	// Get the Landlock version which works for Kernel 6.7+
	llCfg := landlock.V4

	// Collect our rules
	var netRules []landlock.Rule

	// Add rules for TCP port binding
	//for _, port := range cfg.BindTCPPorts {
	//	log.Debug("Adding TCP bind port: %d", port)
	//	net_rules = append(net_rules, landlock.BindTCP(uint16(port)))
	//}

	// Add rules for TCP connections
	for _, port := range cfg.ConnectTCPPorts {
		log.Printf("Adding TCP connect port: %d", port)
		netRules = append(netRules, landlock.ConnectTCP(uint16(port)))
	}

	err := llCfg.RestrictNet(netRules...)
	if err != nil {
		return fmt.Errorf("failed to apply Landlock network restrictions: %w", err)
	}

	return nil
}

func Run(args []string, env []string) error {
	binary, err := exec.LookPath(args[0])
	if err != nil {
		return err
	}

	log.Printf("Executing: %v", args)

	// Only pass the explicitly specified environment variables
	// If env is empty, no environment variables will be passed
	return syscall.Exec(binary, args, env)
}

func main() {
	fmt.Printf("OK\n")

	cfg := Config{
		ConnectTCPPorts: []int{80},
	}
	err := Apply(cfg)
	if err != nil {
		log.Fatalf("failed to apply Landlock network restrictions: %v", err)
	}

	log.Printf("os.Args[1:]: %v", os.Args[1:])

	err = Run(os.Args[1:], os.Environ())
	if err != nil {
		log.Fatalf("failed to apply Landlock network restrictions: %v", err)
	}
}
