package namespace

import (
	"fmt"
	"log/slog"
	"time"
)

const (
	namespacePrefix = "coder_jail"
)

// JailConfig holds configuration for network jail
type Config struct {
	Logger         *slog.Logger
	HttpProxyPort  int
	HttpsProxyPort int
	Env            map[string]string
}

// // NewJail creates a new NetJail instance for the current platform
// func New(config Config) (jail.Commander, error) {
// 	switch runtime.GOOS {
// 	case "darwin":
// 		return NewMacOS(config)
// 	case "linux":
// 		return NewLinux(config)
// 	default:
// 		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
// 	}
// }

func newNamespaceName() string {
	return fmt.Sprintf("%s_%d", namespacePrefix, time.Now().UnixNano()%10000000)
}
