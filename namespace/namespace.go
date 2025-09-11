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

func newNamespaceName() string {
	return fmt.Sprintf("%s_%d", namespacePrefix, time.Now().UnixNano()%10000000)
}
