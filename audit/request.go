package audit

type Auditor interface {
	AuditRequest(req Request)
}

// Request represents information about an HTTP request for auditing
type Request struct {
	Method  string
	URL     string // The fully qualified request URL (scheme, domain, optional path).
	Host    string
	Allowed bool
	Rule    string // The rule that matched (if any)

	// SequenceNumber is a pre-allocated sequence number for this
	// audit event. When non-nil the auditor must use this value
	// instead of generating its own so that the audit log and
	// any injected HTTP header carry the same number. When nil
	// the auditor falls back to its internal SequenceCounter.
	SequenceNumber *uint64
}
