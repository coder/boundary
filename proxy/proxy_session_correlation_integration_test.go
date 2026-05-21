package proxy

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"

	"github.com/coder/boundary/audit"
	"github.com/coder/boundary/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// multiRequestCapturingBackend records the headers from every request it
// receives, not just the last one. This is needed by integration tests
// that send multiple requests to the same backend and want to verify
// each one independently.
type multiRequestCapturingBackend struct {
	server *httptest.Server
	mu     sync.Mutex
	all    []http.Header
}

func newMultiRequestCapturingBackend() *multiRequestCapturingBackend {
	mcb := &multiRequestCapturingBackend{}
	mcb.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mcb.mu.Lock()
		mcb.all = append(mcb.all, r.Header.Clone())
		mcb.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	return mcb
}

var errHeaderIndexOutOfRange = errors.New("headersAt: index out of range")

func (m *multiRequestCapturingBackend) close() { m.server.Close() }

func (m *multiRequestCapturingBackend) requestCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.all)
}

func (m *multiRequestCapturingBackend) headersAt(i int) (http.Header, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if i < 0 || i >= len(m.all) {
		return nil, errHeaderIndexOutOfRange
	}
	return m.all[i].Clone(), nil
}

// correlationTestEnv holds the shared objects for a session-correlation
// integration test: the proxy, auditor, backend(s), and sequence
// counter. Tests build one via newCorrelationTestEnv and tear it down
// with stop.
type correlationTestEnv struct {
	pt      *ProxyTest
	auditor *capturingAuditor
	seq     *audit.SequenceCounter
	// injectBackend expects headers to be injected as these requests
	// are expected to be seen by the AI Gateway and then correlated
	// back to the audit event.
	injectBackend *multiRequestCapturingBackend
	// otherBackend does not expect headers to be injected as these
	// requests should not be routed through the AI Gateway.
	otherBackend *multiRequestCapturingBackend
}

func (s *correlationTestEnv) stop() {
	if s.pt != nil {
		s.pt.Stop()
	}
	if s.injectBackend != nil {
		s.injectBackend.close()
	}
	if s.otherBackend != nil {
		s.otherBackend.close()
	}
}

// newCorrelationTestEnv builds a proxy that allows traffic to two
// httptest backends: one that matches an inject target and one that
// does not (simulating a generic allowed domain like github.com).
// Both backends capture all received request headers. A
// capturingAuditor records every audit event for later inspection.
func newCorrelationTestEnv(t *testing.T, sessionID string) *correlationTestEnv {
	t.Helper()

	inject := newMultiRequestCapturingBackend()
	other := newMultiRequestCapturingBackend()

	injectURL, err := url.Parse(inject.server.URL)
	require.NoError(t, err)

	otherURL, err := url.Parse(other.server.URL)
	require.NoError(t, err)

	aud := &capturingAuditor{}
	seq := &audit.SequenceCounter{}

	// Both httptest backends resolve to 127.0.0.1, so a domain-only
	// inject target would match both. We use a path glob on the
	// inject-target paths (/v1/*) to limit header injection.
	pt := NewProxyTest(t,
		WithCertManager(t.TempDir()),
		// Allow both backends.
		WithAllowedDomain(injectURL.Hostname()),
		WithAllowedDomain(otherURL.Hostname()),
		// Only requests matching the inject-target path receive headers.
		WithSessionCorrelation(config.SessionCorrelationConfig{
			Enabled:       true,
			InjectTargets: []string{"domain=" + injectURL.Hostname() + " path=/v1/*"},
		}),
		WithSessionID(sessionID),
		WithAuditor(aud),
	).Start()

	return &correlationTestEnv{
		pt:            pt,
		auditor:       aud,
		seq:           seq,
		injectBackend: inject,
		otherBackend:  other,
	}
}

// TestIntegration_LLMRequestAuditAndHeadersAgree verifies the core
// correlation invariant: when an allowed request hits an inject target,
// the sequence number in the audit event equals the sequence number in
// the forwarded header.
func TestIntegration_LLMRequestAuditAndHeadersAgree(t *testing.T) {
	// Given: a proxy with session correlation enabled and an inject-target backend.
	const sessionID = "e5f6a7b8-c9d0-4e1f-8a2b-3c4d5e6f7a8b"
	s := newCorrelationTestEnv(t, sessionID)
	defer s.stop()

	// Precondition: no audit events exist before the request.
	require.Empty(t, s.auditor.getRequests(), "no audit events should exist before the request")

	// When: a single request is sent to the inject-target backend.
	s.pt.ExpectGetViaProxy(s.injectBackend.server.URL+"/v1/messages", http.StatusOK)

	// Then: the audit event records the correct sequence number.
	events := s.auditor.getRequests()
	require.Len(t, events, 1)
	require.True(t, events[0].Allowed)
	assert.Equal(t, int32(0), events[0].SequenceNumber)

	// Then: the forwarded request carries the session ID and sequence number headers.
	require.Equal(t, 1, s.injectBackend.requestCount())
	headers, err := s.injectBackend.headersAt(0)
	require.NoError(t, err)
	require.NotNil(t, headers)
	assert.Equal(t, sessionID, headers.Get(config.SessionIDHeaderName))
	assert.Equal(t, "0", headers.Get(config.SequenceNumberHeaderName))

	// Then: the audit event and forwarded header agree on the sequence number.
	assert.Equal(t,
		strconv.Itoa(int(events[0].SequenceNumber)),
		headers.Get(config.SequenceNumberHeaderName),
		"audit event and forwarded header must carry the same sequence number",
	)
}

// TestIntegration_NonLLMRequestAuditedWithoutHeaders verifies that an
// allowed request to a domain that is NOT an inject target still gets
// audited (with a sequence number) but does NOT receive correlation
// headers.
func TestIntegration_NonLLMRequestAuditedWithoutHeaders(t *testing.T) {
	// Given: a proxy with session correlation enabled and a non-inject-target backend.
	s := newCorrelationTestEnv(t, "test-session")
	defer s.stop()

	// When: a request is sent to the non-inject-target backend.
	s.pt.ExpectGetViaProxy(s.otherBackend.server.URL+"/pulls", http.StatusOK)

	// Then: an audit event is recorded with a sequence number.
	events := s.auditor.getRequests()
	require.Len(t, events, 1)
	require.True(t, events[0].Allowed)
	assert.Equal(t, int32(0), events[0].SequenceNumber)

	// Then: no correlation headers are present on the forwarded request.
	require.Equal(t, 1, s.otherBackend.requestCount())
	headers, err := s.otherBackend.headersAt(0)
	require.NoError(t, err)
	require.NotNil(t, headers)
	assert.Empty(t, headers.Get(config.SessionIDHeaderName),
		"non-inject-target requests must not carry session ID header")
	assert.Empty(t, headers.Get(config.SequenceNumberHeaderName),
		"non-inject-target requests must not carry sequence number header")
}

// TestIntegration_DeniedRequestAuditedNeverForwarded verifies that a
// request denied by the rules engine is audited (consuming a sequence
// number) but is never forwarded to any backend.
func TestIntegration_DeniedRequestAuditedNeverForwarded(t *testing.T) {
	// Given: a proxy with no allowed domains (deny-all configuration).
	backend := newMultiRequestCapturingBackend()
	defer backend.close()

	aud := &capturingAuditor{}

	pt := NewProxyTest(t,
		WithCertManager(t.TempDir()),
		WithSessionCorrelation(config.SessionCorrelationConfig{
			Enabled:       true,
			InjectTargets: []string{"domain=anything.example.com"},
		}),
		WithSessionID("test-session"),
		WithAuditor(aud),
	).Start()
	defer pt.Stop()

	// When: a request is sent to a domain that is not allowed.
	pt.ExpectGetViaProxy(backend.server.URL+"/exfil", http.StatusForbidden)

	// Then: an audit event is recorded with the denied flag and a sequence number.
	events := aud.getRequests()
	require.Len(t, events, 1)
	require.False(t, events[0].Allowed)
	assert.Equal(t, int32(0), events[0].SequenceNumber)

	// Then: the backend never receives the request.
	assert.Equal(t, 0, backend.requestCount(),
		"denied requests must not be forwarded to the backend")
}

// TestIntegration_SequenceGapAcrossMixedRequests sends two inject-target
// requests bookending three allowed tool-use requests and one denied
// request, then verifies:
//  1. Sequence numbers increase monotonically across all six events.
//  2. Only inject-target requests carry correlation headers.
//  3. The session ID and sequence number in headers match the audit events.
//  4. The gap of 4 between the two inject-target sequence numbers (0 and 5)
//     precisely accounts for the three allowed tool-use requests and the
//     one denied request in between.
func TestIntegration_SequenceGapAcrossMixedRequests(t *testing.T) {
	const sessionID = "mixed-session"

	// Given: a proxy with an inject-target and a non-inject-target backend.
	s := newCorrelationTestEnv(t, sessionID)
	defer s.stop()

	// When: a request is sent to the inject-target backend.
	s.pt.ExpectGetViaProxy(s.injectBackend.server.URL+"/v1/messages", http.StatusOK)

	for _, p := range []string{"/coder/coder", "/coder/coder/issues", "/coder/coder/pulls"} {
		// When: a request is sent to the non-inject-target backend.
		s.pt.ExpectGetViaProxy(s.otherBackend.server.URL+p, http.StatusOK)
	}

	// When: a request is sent to a domain that is not allowed.
	s.pt.ExpectGetViaProxy("http://evil.example.com/exfil", http.StatusForbidden)

	// When: a request is sent to the inject-target backend.
	s.pt.ExpectGetViaProxy(s.injectBackend.server.URL+"/v1/messages", http.StatusOK)

	// Then: all six events are audited with monotonically increasing
	// sequence numbers and correct allowed flags.
	events := s.auditor.getRequests()
	require.Len(t, events, 6, "expected exactly six audit events")

	expectedAllowed := []bool{true, true, true, true, false, true}
	for i, ev := range events {
		assert.Equal(t, int32(i), ev.SequenceNumber,
			"event %d: wrong sequence number", i)
		assert.Equal(t, expectedAllowed[i], ev.Allowed,
			"event %d: wrong allowed flag", i)
	}

	// Then: the inject-target backend receives correlation headers with
	// the correct session ID and sequence numbers.
	require.Equal(t, 2, s.injectBackend.requestCount(),
		"inject-target backend should have received exactly two requests")

	firstInjectHeaders, err := s.injectBackend.headersAt(0)
	require.NoError(t, err)
	require.NotNil(t, firstInjectHeaders)
	assert.Equal(t, sessionID, firstInjectHeaders.Get(config.SessionIDHeaderName))
	assert.Equal(t, "0", firstInjectHeaders.Get(config.SequenceNumberHeaderName),
		"first inject-target request must have sequence 0")

	secondInjectHeaders, err := s.injectBackend.headersAt(1)
	require.NoError(t, err)
	require.NotNil(t, secondInjectHeaders)
	assert.Equal(t, sessionID, secondInjectHeaders.Get(config.SessionIDHeaderName))
	assert.Equal(t, "5", secondInjectHeaders.Get(config.SequenceNumberHeaderName),
		"second inject-target request must have sequence 5")

	// Then: the non-inject-target backend receives no correlation headers
	// on any of its three requests.
	require.Equal(t, 3, s.otherBackend.requestCount())
	for i := 0; i < 3; i++ {
		h, err := s.otherBackend.headersAt(i)
		require.NoError(t, err)
		require.NotNil(t, h)
		assert.Empty(t, h.Get(config.SessionIDHeaderName),
			"other backend request %d must not carry session ID header", i)
		assert.Empty(t, h.Get(config.SequenceNumberHeaderName),
			"other backend request %d must not carry sequence number header", i)
	}

	// Then: the gap of 4 between inject-target sequence numbers (0 and 5)
	// accounts for the three tool-use requests and the one denied request.
	gap := events[5].SequenceNumber - events[0].SequenceNumber - 1
	assert.Equal(t, int32(4), gap,
		"gap between inject-target requests should reveal 4 intermediate events")
}

// TestIntegration_SpoofedHeadersOverwrittenWithCorrectSequence
// verifies that when a jailed client sets its own correlation headers,
// the proxy replaces them with the real session ID and the real
// sequence number, and the audit event still agrees with the header.
func TestIntegration_SpoofedHeadersOverwrittenWithCorrectSequence(t *testing.T) {
	// Given: a proxy with session correlation enabled.
	const sessionID = "real-session-uuid"
	s := newCorrelationTestEnv(t, sessionID)
	defer s.stop()

	// When: a request is sent with spoofed correlation headers.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, s.injectBackend.server.URL+"/v1/messages", nil)
	require.NoError(t, err)
	req.Header.Set(config.SessionIDHeaderName, "spoofed-session")
	req.Header.Set(config.SequenceNumberHeaderName, "9999")

	resp, err := s.pt.proxyClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Then: the backend receives the real values, not the spoofed ones.
	require.Equal(t, 1, s.injectBackend.requestCount())
	headers, err := s.injectBackend.headersAt(0)
	require.NoError(t, err)
	require.NotNil(t, headers)
	assert.Equal(t, sessionID, headers.Get(config.SessionIDHeaderName))
	assert.Equal(t, "0", headers.Get(config.SequenceNumberHeaderName))

	// Then: the audit event agrees with the forwarded header.
	events := s.auditor.getRequests()
	require.Len(t, events, 1)
	assert.Equal(t,
		strconv.Itoa(int(events[0].SequenceNumber)),
		headers.Get(config.SequenceNumberHeaderName),
	)
}

// TestIntegration_DisabledCorrelationNoHeaders verifies that when
// session correlation is disabled, the proxy does not inject
// correlation headers even for requests that match an inject target.
// Note: the sequence counter is a value type on the proxy server and
// always increments regardless of the correlation setting, so we only
// assert on the absence of headers here.
func TestIntegration_DisabledCorrelationNoHeaders(t *testing.T) {
	// Given: a proxy with session correlation disabled.
	backend := newMultiRequestCapturingBackend()
	defer backend.close()

	backendURL, err := url.Parse(backend.server.URL)
	require.NoError(t, err)

	aud := &capturingAuditor{}

	pt := NewProxyTest(t,
		WithCertManager(t.TempDir()),
		WithAllowedDomain(backendURL.Hostname()),
		WithSessionCorrelation(config.SessionCorrelationConfig{
			Enabled:       false,
			InjectTargets: []string{"domain=" + backendURL.Hostname()},
		}),
		WithSessionID("should-not-appear"),
		WithAuditor(aud),
	).Start()
	defer pt.Stop()

	// When: a request is sent that would match an inject target.
	pt.ExpectGetViaProxy(backend.server.URL+"/v1/messages", http.StatusOK)

	// Then: no correlation headers are injected on the forwarded request.
	require.Equal(t, 1, backend.requestCount())
	headers, err := backend.headersAt(0)
	require.NoError(t, err)
	require.NotNil(t, headers)
	assert.Empty(t, headers.Get(config.SessionIDHeaderName),
		"session ID header must not be injected when correlation is disabled")
	assert.Empty(t, headers.Get(config.SequenceNumberHeaderName),
		"sequence number header must not be injected when correlation is disabled")

	// Then: the request is still audited.
	events := aud.getRequests()
	require.Len(t, events, 1)
	require.True(t, events[0].Allowed)
}

// TestIntegration_ConcurrentRequestsUniqueSequenceNumbers sends
// multiple requests concurrently and verifies that every request
// receives a unique sequence number, and that the set of numbers is
// dense (no gaps, no duplicates).
func TestIntegration_ConcurrentRequestsUniqueSequenceNumbers(t *testing.T) {
	const sessionID = "concurrent-session"
	const numRequests = 10

	// Given: a proxy with session correlation enabled.
	s := newCorrelationTestEnv(t, sessionID)
	defer s.stop()

	// When: multiple requests are sent concurrently to the inject-target backend.
	var wg sync.WaitGroup
	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, s.injectBackend.server.URL+"/v1/messages", nil)
			assert.NoError(t, err)
			resp, err := s.pt.proxyClient.Do(req)
			assert.NoError(t, err)
			if resp != nil {
				resp.Body.Close() //nolint:errcheck
			}
		}()
	}
	wg.Wait()

	// Then: every request is audited.
	events := s.auditor.getRequests()
	require.Len(t, events, numRequests)

	// Then: each audit event has a unique sequence number.
	seen := make(map[int32]bool, numRequests)
	for i, ev := range events {
		assert.False(t, seen[ev.SequenceNumber],
			"event %d: duplicate sequence number %d", i, ev.SequenceNumber)
		seen[ev.SequenceNumber] = true
	}

	// Then: the sequence numbers form a dense set {0, 1, ..., numRequests-1}.
	for i := int32(0); i < numRequests; i++ {
		assert.True(t, seen[i],
			"sequence number %d is missing from the set", i)
	}

	// Then: every forwarded request header carries a matching sequence number.
	require.Equal(t, numRequests, s.injectBackend.requestCount())
	headerSeqs := make(map[string]bool, numRequests)
	for i := 0; i < numRequests; i++ {
		headers, err := s.injectBackend.headersAt(i)
		require.NoError(t, err)
		require.NotNil(t, headers)
		seqStr := headers.Get(config.SequenceNumberHeaderName)
		assert.NotEmpty(t, seqStr, "request %d: sequence header must be set", i)
		headerSeqs[seqStr] = true
	}
	for i := int32(0); i < numRequests; i++ {
		assert.True(t, headerSeqs[fmt.Sprintf("%d", i)],
			"header sequence number %d is missing", i)
	}
}
