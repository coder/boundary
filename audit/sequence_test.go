package audit

import (
	"sync"
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
	for i := range uint64(100) {
		if got := c.Next(); got != i {
			t.Fatalf("call %d: got %d, want %d", i, got, i)
		}
	}
}

func TestSequenceCounter_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	var c SequenceCounter

	const goroutines = 8
	const callsPerGoroutine = 1000
	const total = goroutines * callsPerGoroutine

	seen := make([]bool, total)
	var mu sync.Mutex

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			for range callsPerGoroutine {
				n := c.Next()
				mu.Lock()
				if n >= total {
					mu.Unlock()
					t.Errorf("sequence number %d out of range [0, %d)", n, total)
					return
				}
				if seen[n] {
					mu.Unlock()
					t.Errorf("duplicate sequence number %d", n)
					return
				}
				seen[n] = true
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	for i, ok := range seen {
		if !ok {
			t.Errorf("sequence number %d was never produced", i)
		}
	}
}

func TestSequenceCounter_IndependentInstances(t *testing.T) {
	t.Parallel()

	var a, b SequenceCounter

	// Advance a a few times.
	for range 5 {
		a.Next()
	}

	// b should still start at 0.
	if got := b.Next(); got != 0 {
		t.Fatalf("independent counter: got %d, want 0", got)
	}
}
