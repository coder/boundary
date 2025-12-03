package testenv

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIPTablesCleanup(t *testing.T) {
	initialRules := snapshotIPTables(t)
	env := NewTestEnv(t,
		WithAllowRule("domain=dev.coder.com"),
	)

	env.Start()
	env.Cleanup()
	endRules := snapshotIPTables(t)

	require.Equal(env.t, initialRules.filterRules, endRules.filterRules,
		"Filter table rules should be restored after cleanup")
	require.Equal(env.t, initialRules.natRules, endRules.natRules,
		"NAT table rules should be restored after cleanup")
}
