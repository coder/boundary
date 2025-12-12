package nsjail

import (
	"fmt"
	"log"
	"os/exec"
	"syscall"
)

type command struct {
	description string
	cmd         *exec.Cmd
	ambientCaps []uintptr
}

type commandRunner struct {
	commands []*command
}

func newCommandRunner(commands []*command) *commandRunner {
	return &commandRunner{
		commands: commands,
	}
}

func (r *commandRunner) run() error {
	for _, command := range r.commands {
		command.cmd.SysProcAttr = &syscall.SysProcAttr{
			AmbientCaps: command.ambientCaps,
		}

		output, err := command.cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to %s: %v, output: %s", command.description, err, output)
		}
	}

	return nil
}

func (r *commandRunner) runIgnoreErrors() error {
	for _, command := range r.commands {
		command.cmd.SysProcAttr = &syscall.SysProcAttr{
			AmbientCaps: command.ambientCaps,
		}

		output, err := command.cmd.CombinedOutput()
		if err != nil {
			log.Printf("failed to %s: %v, output: %s", command.description, err, output)
			continue
		}
	}

	return nil
}
