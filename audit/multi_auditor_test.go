package audit

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type mockAuditor struct {
	requests []Request
	closed   bool
}

func (m *mockAuditor) AuditRequest(req Request) {
	m.requests = append(m.requests, req)
}

func (m *mockAuditor) Close() error {
	m.closed = true
	return nil
}

func TestMultiAuditor_AuditRequest(t *testing.T) {
	mock1 := &mockAuditor{}
	mock2 := &mockAuditor{}

	multi := NewMultiAuditor(mock1, mock2)

	req := Request{
		Method:  "GET",
		URL:     "https://example.com",
		Host:    "example.com",
		Allowed: true,
		Rule:    "domain=example.com",
	}

	multi.AuditRequest(req)

	assert.Len(t, mock1.requests, 1)
	assert.Len(t, mock2.requests, 1)
	assert.Equal(t, req, mock1.requests[0])
	assert.Equal(t, req, mock2.requests[0])
}

func TestMultiAuditor_Close(t *testing.T) {
	mock1 := &mockAuditor{}
	mock2 := &mockAuditor{}

	multi := NewMultiAuditor(mock1, mock2)
	err := multi.Close()

	assert.NoError(t, err)
	assert.True(t, mock1.closed)
	assert.True(t, mock2.closed)
}
