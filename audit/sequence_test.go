package audit

import (
	"testing"
)

func TestSequenceCounter_StartsAtZero(t *testing.T) {
	t.Parallel()

	var c SequenceCounter
	if got := c.Next(); got != 0 {
		t.Fatalf("first call: got %d, want 0", got)
	}
}

func TestSequenceCounter_Increments(t *testing.T) {
	t.Parallel()

	var c SequenceCounter
	for i := range int32(100) {
		if got := c.Next(); got != i {
			t.Fatalf("call %d: got %d, want %d", i, got, i)
		}
	}
}
