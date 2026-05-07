package proxy

import (
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

func (m *multiRequestCapturingBackend) close() { m.server.Close() }

func (m *multiRequestCapturingBackend) requestCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.all)
}

func (m *multiRequestCapturingBackend) headersAt(i int) http.Header {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.all[i].Clone()
}

// sessionCorrelationIntegrationSetup holds the shared objects for an
// integration test: the proxy, auditor, backend(s), and sequence
// counter. Tests build one via newSessionCorrelationIntegrationSetup
// and tear it down with stop.
type sessionCorrelationIntegrationSetup struct {
	pt           *ProxyTest
	auditor      *capturingAuditor
	seq          *audit.SequenceCounter
	llmBackend   *multiRequestCapturingBackend
	otherBackend *multiRequestCapturingBackend
}

func (s *sessionCorrelationIntegrationSetup) stop() {
	s.pt.Stop()
	if s.llmBackend != nil {
		s.llmBackend.close()
	}
	if s.otherBackend != nil {
		s.otherBackend.close()
	}
}

// newSessionCorrelationIntegrationSetup builds a proxy that allows
// traffic to two httptest backends: one that matches an inject target
// (simulating an LLM provider) and one that does not (simulating a
// generic allowed domain like github.com). Both backends capture all
// received request headers. A capturingAuditor records every audit
// event for later inspection.
func newSessionCorrelationIntegrationSetup(t *testing.T, sessionID string) *sessionCorrelationIntegrationSetup {
	t.Helper()

	llm := newMultiRequestCapturingBackend()
	other := newMultiRequestCapturingBackend()

	llmURL, err := url.Parse(llm.server.URL)
	require.NoError(t, err)

	otherURL, err := url.Parse(other.server.URL)
	require.NoError(t, err)

	aud := &capturingAuditor{}
	seq := &audit.SequenceCounter{}

	// Both httptest backends resolve to 127.0.0.1, so a domain-only
	// inject target would match both. We use a path glob on the LLM
	// paths (/v1/*) to limit header injection to LLM requests.
	pt := NewProxyTest(t,
		WithCertManager(t.TempDir()),
		// Allow both backends.
		WithAllowedDomain(llmURL.Hostname()),
		WithAllowedDomain(otherURL.Hostname()),
		// Only requests matching the LLM path receive headers.
		WithSessionCorrelation(config.SessionCorrelationConfig{
			Enabled: true,
			InjectTargets: []config.InjectTarget{{
				Domain: llmURL.Hostname(),
				Path:   "/v1/*",
			}},
		}),
		WithSessionID(sessionID),
		WithAuditor(aud),
	).Start()

	return &sessionCorrelationIntegrationSetup{
		pt:           pt,
		auditor:      aud,
		seq:          seq,
		llmBackend:   llm,
		otherBackend: other,
	}
}

// ---------- Integration Tests ----------

// TestIntegration_LLMRequestAuditAndHeadersAgree verifies the core
// correlation invariant: when an allowed request hits an inject target,
// the sequence number in the audit event equals the sequence number in
// the forwarded header.
func TestIntegration_LLMRequestAuditAndHeadersAgree(t *testing.T) {
	const sessionID = "e5f6a7b8-0000-0000-0000-000000000000"
	s := newSessionCorrelationIntegrationSetup(t, sessionID)
	defer s.stop()

	resp, err := s.pt.proxyClient.Get(s.llmBackend.server.URL + "/v1/messages")
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Audit event.
	events := s.auditor.getRequests()
	require.Len(t, events, 1)
	require.True(t, events[0].Allowed)
	require.NotNil(t, events[0].SequenceNumber)
	assert.Equal(t, int32(0), events[0].SequenceNumber)

	// Forwarded headers.
	require.Equal(t, 1, s.llmBackend.requestCount())
	hdr := s.llmBackend.headersAt(0)
	assert.Equal(t, sessionID, hdr.Get(config.SessionIDHeaderName))
	assert.Equal(t, "0", hdr.Get(config.SequenceNumberHeaderName))

	// The two must agree.
	assert.Equal(t,
		strconv.Itoa(int(events[0].SequenceNumber)),
		hdr.Get(config.SequenceNumberHeaderName),
		"audit event and forwarded header must carry the same sequence number",
	)
}

// TestIntegration_NonLLMRequestAuditedWithoutHeaders verifies that an
// allowed request to a domain that is NOT an inject target still gets
// audited (with a sequence number) but does NOT receive correlation
// headers.
func TestIntegration_NonLLMRequestAuditedWithoutHeaders(t *testing.T) {
	s := newSessionCorrelationIntegrationSetup(t, "test-session")
	defer s.stop()

	resp, err := s.pt.proxyClient.Get(s.otherBackend.server.URL + "/pulls")
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Audit event recorded.
	events := s.auditor.getRequests()
	require.Len(t, events, 1)
	require.True(t, events[0].Allowed)
	require.NotNil(t, events[0].SequenceNumber)
	assert.Equal(t, int32(0), events[0].SequenceNumber)

	// No correlation headers on the backend.
	require.Equal(t, 1, s.otherBackend.requestCount())
	hdr := s.otherBackend.headersAt(0)
	assert.Empty(t, hdr.Get(config.SessionIDHeaderName),
		"non-inject-target requests must not carry session ID header")
	assert.Empty(t, hdr.Get(config.SequenceNumberHeaderName),
		"non-inject-target requests must not carry sequence number header")
}

// TestIntegration_DeniedRequestAuditedNeverForwarded verifies that a
// request denied by the rules engine is audited (consuming a sequence
// number) but is never forwarded to any backend.
func TestIntegration_DeniedRequestAuditedNeverForwarded(t *testing.T) {
	// Create a setup with a custom deny-all proxy, but keep the same
	// pattern of shared sequence counter and auditor.
	llm := newMultiRequestCapturingBackend()
	defer llm.close()

	aud := &capturingAuditor{}

	pt := NewProxyTest(t,
		WithCertManager(t.TempDir()),
		// No allowed domains: deny everything.
		WithSessionCorrelation(config.SessionCorrelationConfig{
			Enabled:       true,
			InjectTargets: []config.InjectTarget{{Domain: "anything.example.com"}},
		}),
		WithSessionID("test-session"),
		WithAuditor(aud),
	).Start()
	defer pt.Stop()

	resp, err := pt.proxyClient.Get(llm.server.URL + "/exfil")
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusForbidden, resp.StatusCode)

	// Audit event recorded.
	events := aud.getRequests()
	require.Len(t, events, 1)
	require.False(t, events[0].Allowed)
	require.NotNil(t, events[0].SequenceNumber)
	assert.Equal(t, int32(0), events[0].SequenceNumber)

	// Backend never hit.
	assert.Equal(t, 0, llm.requestCount(),
		"denied requests must not be forwarded to the backend")
}

// TestIntegration_MixedRequestsSequenceOrdering sends a realistic
// sequence of LLM, non-LLM, and denied requests, then verifies:
//  1. Sequence numbers increase monotonically across all request types.
//  2. Only inject-target requests carry correlation headers.
//  3. The sequence numbers in headers match the audit events.
//  4. The gap between two LLM requests' sequence numbers reveals the
//     intermediate non-LLM and denied activity.
func TestIntegration_MixedRequestsSequenceOrdering(t *testing.T) {
	const sessionID = "mixed-test-session"

	// Two allowed backends (LLM and "github"), one denied domain.
	llm := newMultiRequestCapturingBackend()
	defer llm.close()

	other := newMultiRequestCapturingBackend()
	defer other.close()

	llmURL, err := url.Parse(llm.server.URL)
	require.NoError(t, err)

	otherURL, err := url.Parse(other.server.URL)
	require.NoError(t, err)

	aud := &capturingAuditor{}

	pt := NewProxyTest(t,
		WithCertManager(t.TempDir()),
		WithAllowedDomain(llmURL.Hostname()),
		WithAllowedDomain(otherURL.Hostname()),
		// Only LLM is an inject target.
		WithSessionCorrelation(config.SessionCorrelationConfig{
			Enabled: true,
			InjectTargets: []config.InjectTarget{{
				Domain: llmURL.Hostname(),
				Path:   "/v1/*",
			}},
		}),
		WithSessionID(sessionID),
		WithAuditor(aud),
	).Start()
	defer pt.Stop()

	// Request 0: LLM (allowed, inject target).
	resp, err := pt.proxyClient.Get(llm.server.URL + "/v1/messages")
	require.NoError(t, err)
	resp.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Request 1: non-LLM (allowed, no inject).
	resp, err = pt.proxyClient.Get(other.server.URL + "/coder/coder")
	require.NoError(t, err)
	resp.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Request 2: denied (nothing is allowed for evil.example.com).
	resp, err = pt.proxyClient.Get("http://evil.example.com/exfil")
	require.NoError(t, err)
	resp.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusForbidden, resp.StatusCode)

	// Request 3: LLM again.
	resp, err = pt.proxyClient.Get(llm.server.URL + "/v1/messages")
	require.NoError(t, err)
	resp.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// -- Verify audit events --
	events := aud.getRequests()
	require.Len(t, events, 4, "expected exactly four audit events")

	expectedSeq := []int32{0, 1, 2, 3}
	expectedAllowed := []bool{true, true, false, true}
	for i, ev := range events {
		require.NotNil(t, ev.SequenceNumber, "event %d: sequence number must be set", i)
		assert.Equal(t, expectedSeq[i], ev.SequenceNumber,
			"event %d: wrong sequence number", i)
		assert.Equal(t, expectedAllowed[i], ev.Allowed,
			"event %d: wrong allowed flag", i)
	}

	// -- Verify LLM backend headers --
	require.Equal(t, 2, llm.requestCount(),
		"LLM backend should have received exactly two requests")

	firstLLMHdr := llm.headersAt(0)
	assert.Equal(t, sessionID, firstLLMHdr.Get(config.SessionIDHeaderName))
	assert.Equal(t, "0", firstLLMHdr.Get(config.SequenceNumberHeaderName),
		"first LLM request must have sequence 0")

	secondLLMHdr := llm.headersAt(1)
	assert.Equal(t, sessionID, secondLLMHdr.Get(config.SessionIDHeaderName))
	assert.Equal(t, "3", secondLLMHdr.Get(config.SequenceNumberHeaderName),
		"second LLM request must have sequence 3")

	// -- Verify non-LLM backend has no correlation headers --
	require.Equal(t, 1, other.requestCount())
	otherHdr := other.headersAt(0)
	assert.Empty(t, otherHdr.Get(config.SessionIDHeaderName))
	assert.Empty(t, otherHdr.Get(config.SequenceNumberHeaderName))

	// -- Verify the gap reveals intermediate activity --
	// The gap between the two LLM sequence numbers (0 and 3) means
	// that sequence numbers 1 and 2 were consumed by non-LLM
	// activity, matching audit events 1 (non-LLM allowed) and 2
	// (denied).
	firstLLMSeq := events[0].SequenceNumber
	secondLLMSeq := events[3].SequenceNumber
	gap := secondLLMSeq - firstLLMSeq - 1
	assert.Equal(t, int32(2), gap,
		"gap between LLM requests should reveal 2 intermediate events")
}

// TestIntegration_SequenceGapRevealsAgenticLoop sends two LLM requests
// with several non-LLM requests in between, simulating an agentic loop
// where the model triggers tool-use HTTP calls between prompts. The
// test verifies that the gap in LLM sequence numbers precisely
// reflects the count of intermediate boundary events.
func TestIntegration_SequenceGapRevealsAgenticLoop(t *testing.T) {
	const sessionID = "agentic-loop-session"

	llm := newMultiRequestCapturingBackend()
	defer llm.close()

	other := newMultiRequestCapturingBackend()
	defer other.close()

	llmURL, err := url.Parse(llm.server.URL)
	require.NoError(t, err)

	otherURL, err := url.Parse(other.server.URL)
	require.NoError(t, err)

	aud := &capturingAuditor{}

	pt := NewProxyTest(t,
		WithCertManager(t.TempDir()),
		WithAllowedDomain(llmURL.Hostname()),
		WithAllowedDomain(otherURL.Hostname()),
		WithSessionCorrelation(config.SessionCorrelationConfig{
			Enabled: true,
			InjectTargets: []config.InjectTarget{{
				Domain: llmURL.Hostname(),
				Path:   "/v1/*",
			}},
		}),
		WithSessionID(sessionID),
		WithAuditor(aud),
	).Start()
	defer pt.Stop()

	// First LLM prompt (seq 0).
	resp, err := pt.proxyClient.Get(llm.server.URL + "/v1/messages")
	require.NoError(t, err)
	resp.Body.Close() //nolint:errcheck

	// Agentic loop: three tool-use HTTP calls.
	for _, p := range []string{"/coder/coder", "/coder/coder/issues", "/coder/coder/pulls"} {
		resp, err = pt.proxyClient.Get(other.server.URL + p)
		require.NoError(t, err)
		resp.Body.Close() //nolint:errcheck
	}

	// Second LLM prompt (seq 4).
	resp, err = pt.proxyClient.Get(llm.server.URL + "/v1/messages")
	require.NoError(t, err)
	resp.Body.Close() //nolint:errcheck

	// Verify LLM sequence headers.
	require.Equal(t, 2, llm.requestCount())
	assert.Equal(t, "0", llm.headersAt(0).Get(config.SequenceNumberHeaderName))
	assert.Equal(t, "4", llm.headersAt(1).Get(config.SequenceNumberHeaderName))

	// The gap between sequence numbers 0 and 4 is 3, matching the
	// three tool-use requests in between.
	events := aud.getRequests()
	require.Len(t, events, 5)

	firstLLMSeq := events[0].SequenceNumber
	secondLLMSeq := events[4].SequenceNumber
	gap := secondLLMSeq - firstLLMSeq - 1
	assert.Equal(t, int32(3), gap,
		"gap between prompts should equal number of tool-use requests")

	// Verify the intermediate events are the tool-use requests.
	for i := 1; i <= 3; i++ {
		require.NotNil(t, events[i].SequenceNumber)
		assert.Equal(t, int32(i), events[i].SequenceNumber)
		assert.True(t, events[i].Allowed)
	}
}

// TestIntegration_SpoofedHeadersOverwrittenWithCorrectSequence
// verifies that when a jailed client sets its own correlation headers,
// the proxy replaces them with the real session ID and the real
// sequence number, and the audit event still agrees with the header.
func TestIntegration_SpoofedHeadersOverwrittenWithCorrectSequence(t *testing.T) {
	const sessionID = "real-session-uuid"
	s := newSessionCorrelationIntegrationSetup(t, sessionID)
	defer s.stop()

	req, err := http.NewRequest(http.MethodPost, s.llmBackend.server.URL+"/v1/messages", nil)
	require.NoError(t, err)
	req.Header.Set(config.SessionIDHeaderName, "spoofed-session")
	req.Header.Set(config.SequenceNumberHeaderName, "9999")

	resp, err := s.pt.proxyClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Backend received real values, not spoofed.
	require.Equal(t, 1, s.llmBackend.requestCount())
	hdr := s.llmBackend.headersAt(0)
	assert.Equal(t, sessionID, hdr.Get(config.SessionIDHeaderName))
	assert.Equal(t, "0", hdr.Get(config.SequenceNumberHeaderName))

	// Audit event agrees with header.
	events := s.auditor.getRequests()
	require.Len(t, events, 1)
	require.NotNil(t, events[0].SequenceNumber)
	assert.Equal(t,
		strconv.Itoa(int(events[0].SequenceNumber)),
		hdr.Get(config.SequenceNumberHeaderName),
	)
}

// TestIntegration_DisabledCorrelationNoHeadersNoPreallocatedSequence
// verifies that when session correlation is disabled, the proxy does
// not inject headers and does not pre-allocate sequence numbers (the
// auditor falls back to its own counter instead).
func TestIntegration_DisabledCorrelationNoHeadersNoPreallocatedSequence(t *testing.T) {
	llm := newMultiRequestCapturingBackend()
	defer llm.close()

	llmURL, err := url.Parse(llm.server.URL)
	require.NoError(t, err)

	aud := &capturingAuditor{}

	pt := NewProxyTest(t,
		WithCertManager(t.TempDir()),
		WithAllowedDomain(llmURL.Hostname()),
		// Correlation disabled; no sequence counter.
		WithSessionCorrelation(config.SessionCorrelationConfig{
			Enabled:       false,
			InjectTargets: []config.InjectTarget{{Domain: llmURL.Hostname()}},
		}),
		WithSessionID("should-not-appear"),
		// Explicitly do NOT set WithSequenceCounter; seqCounter is nil.
		WithAuditor(aud),
	).Start()
	defer pt.Stop()

	resp, err := pt.proxyClient.Get(llm.server.URL + "/v1/messages")
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// No correlation headers.
	require.Equal(t, 1, llm.requestCount())
	hdr := llm.headersAt(0)
	assert.Empty(t, hdr.Get(config.SessionIDHeaderName))
	assert.Empty(t, hdr.Get(config.SequenceNumberHeaderName))

	// Audit event recorded but without a pre-allocated sequence
	// number (nil), because no SequenceCounter was provided.
	events := aud.getRequests()
	require.Len(t, events, 1)
	assert.Equal(t, int32(0), events[0].SequenceNumber,
		"no sequence counter means no pre-allocated sequence number")
}

// TestIntegration_ConcurrentRequestsUniqueSequenceNumbers sends
// multiple requests concurrently and verifies that every request
// receives a unique sequence number, and that the set of numbers is
// dense (no gaps, no duplicates).
func TestIntegration_ConcurrentRequestsUniqueSequenceNumbers(t *testing.T) {
	const sessionID = "concurrent-session"
	const numRequests = 10

	s := newSessionCorrelationIntegrationSetup(t, sessionID)
	defer s.stop()

	var wg sync.WaitGroup
	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := s.pt.proxyClient.Get(s.llmBackend.server.URL + "/v1/messages")
			assert.NoError(t, err)
			if resp != nil {
				resp.Body.Close() //nolint:errcheck
			}
		}()
	}
	wg.Wait()

	// Every request should have been audited.
	events := s.auditor.getRequests()
	require.Len(t, events, numRequests)

	// Collect all sequence numbers and verify uniqueness.
	seen := make(map[int32]bool, numRequests)
	for i, ev := range events {
		require.NotNil(t, ev.SequenceNumber,
			"event %d: sequence number must not be nil", i)
		assert.False(t, seen[ev.SequenceNumber],
			"event %d: duplicate sequence number %d", i, ev.SequenceNumber)
		seen[ev.SequenceNumber] = true
	}

	// The set should be exactly {0, 1, ..., numRequests-1}.
	for i := int32(0); i < numRequests; i++ {
		assert.True(t, seen[i],
			"sequence number %d is missing from the set", i)
	}

	// Every header should also carry a matching sequence number.
	require.Equal(t, numRequests, s.llmBackend.requestCount())
	headerSeqs := make(map[string]bool, numRequests)
	for i := 0; i < numRequests; i++ {
		hdr := s.llmBackend.headersAt(i)
		seqStr := hdr.Get(config.SequenceNumberHeaderName)
		assert.NotEmpty(t, seqStr, "request %d: sequence header must be set", i)
		headerSeqs[seqStr] = true
	}
	for i := int32(0); i < numRequests; i++ {
		assert.True(t, headerSeqs[fmt.Sprintf("%d", i)],
			"header sequence number %d is missing", i)
	}
}
