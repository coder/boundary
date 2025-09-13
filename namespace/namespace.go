package namespace

import (
	"log/slog"
	"os/exec"
)

type Commander interface {
	Start() error
	Command(command []string) *exec.Cmd
	Close() error
}

type Config struct {
	Logger        *slog.Logger
	HttpProxyPort int
	TlsConfigDir  string
	CACertPath    string
	UserInfo      UserInfo
}

type UserInfo struct {
	Username  string
	Uid       int
	Gid       int
	HomeDir   string
	ConfigDir string
}
