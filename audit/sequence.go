package audit

import "sync/atomic"

// SequenceCounter is a monotonically increasing counter that assigns a
// unique sequence number to every audit event within a single boundary
// session. The counter starts at 0 and is safe for concurrent use by
// both the socket auditor and the proxy.
type SequenceCounter struct {
	next atomic.Uint64
}

// Next returns the next sequence number. The first call returns 0,
// subsequent calls return 1, 2, 3, etc. It is safe for concurrent
// use.
func (c *SequenceCounter) Next() uint64 {
	// Add returns the new value after incrementing, so subtract 1
	// to produce a zero-based sequence.
	return c.next.Add(1) - 1
}
