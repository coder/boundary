package audit

type Auditor interface {
	AuditRequest(req Request)
}

// Request represents information about an HTTP request for auditing
type Request struct {
	Method  string
	URL     string
	Allowed bool
	Rule    string // The rule that matched (if any)
}
