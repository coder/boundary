package jail

import "os/exec"

type Commander interface {
	Open() error
	Command(command []string) *exec.Cmd
	Close() error
}

type Config struct {
	CommandExecutor Commander
}

type Jail struct {
	commandExecutor Commander
	// proxy server
	// tls manager
}

func New(config Config) *Jail {
	return &Jail{
		commandExecutor: config.CommandExecutor,
	}
}

func (j *Jail) Open() error {
	return j.commandExecutor.Open()
}

func (j *Jail) Command(command []string) *exec.Cmd {
	return j.commandExecutor.Command(command)
}

func (j *Jail) Close() error {
	return j.commandExecutor.Close()
}
