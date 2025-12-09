package audit

// MultiAuditor wraps multiple auditors and sends requests to all of them.
type MultiAuditor struct {
	auditors []Auditor
}

// NewMultiAuditor creates an auditor that forwards requests to all provided auditors.
func NewMultiAuditor(auditors ...Auditor) *MultiAuditor {
	return &MultiAuditor{
		auditors: auditors,
	}
}

// AuditRequest sends the request to all wrapped auditors.
func (m *MultiAuditor) AuditRequest(req Request) {
	for _, a := range m.auditors {
		a.AuditRequest(req)
	}
}
