package namespace

import (
	"fmt"
	"time"
)

const (
	prefix = "coder_jail"
)

func newNamespaceName() string {
	return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano()%10000000)
}
