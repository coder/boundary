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

	// SequenceNumber is the sequence number assigned to this audit event
	// by the proxy. It is monotonically increasing within a session and
	// is shared with any injected HTTP header so both carry the same value.
	SequenceNumber int32
}
