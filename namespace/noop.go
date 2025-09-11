package namespace

import (
	"os/exec"
)

type noop struct{}

func newNoop(_ Config) (*noop, error) {
	return &noop{}, nil
}

func (n *noop) Command(_ []string) *exec.Cmd {
	return exec.Command("true")
}

func (n *noop) Start() error {
	return nil
}

func (n *noop) Close() error {
	return nil
}
