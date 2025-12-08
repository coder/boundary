package audit

// MultiAuditor wraps multiple Auditor implementations and calls AuditRequest
// on all of them. This ensures that stdout logging (via LogAuditor) remains
// active even when other auditors like OTLP or Socket are configured.
type MultiAuditor struct {
	auditors []Auditor
}

// NewMultiAuditor creates a MultiAuditor that delegates to all provided auditors.
func NewMultiAuditor(auditors ...Auditor) *MultiAuditor {
	return &MultiAuditor{
		auditors: auditors,
	}
}

// AuditRequest calls AuditRequest on all wrapped auditors.
func (m *MultiAuditor) AuditRequest(req Request) {
	for _, a := range m.auditors {
		a.AuditRequest(req)
	}
}

// Close closes all auditors that implement io.Closer.
func (m *MultiAuditor) Close() error {
	var lastErr error
	for _, a := range m.auditors {
		if closer, ok := a.(interface{ Close() error }); ok {
			if err := closer.Close(); err != nil {
				lastErr = err
			}
		}
	}
	return lastErr
}
