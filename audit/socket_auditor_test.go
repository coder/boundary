package audit

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/coder/v2/agent/boundarylogproxy/codec"
	agentproto "github.com/coder/coder/v2/agent/proto"
)

func TestSocketAuditor_AuditRequest_QueuesLog(t *testing.T) {
	t.Parallel()

	auditor := setupSocketAuditor(t)

	auditor.AuditRequest(Request{
		Method:  "GET",
		URL:     "https://example.com",
		Host:    "example.com",
		Allowed: true,
		Rule:    "allow-all",
	})

	select {
	case log := <-auditor.logCh:
		if log.Allowed != true {
			t.Errorf("expected Allowed=true, got %v", log.Allowed)
		}
		if log.Time == nil {
			t.Fatal("expected Time to be set")
		}
		if log.SequenceNumber != 0 {
			t.Errorf("expected first SequenceNumber=0, got %d", log.SequenceNumber)
		}
		httpReq := log.GetHttpRequest()
		if httpReq == nil {
			t.Fatal("expected HttpRequest, got nil")
		}
		if httpReq.Method != "GET" {
			t.Errorf("expected Method=GET, got %s", httpReq.Method)
		}
		if httpReq.Url != "https://example.com" {
			t.Errorf("expected URL=https://example.com, got %s", httpReq.Url)
		}
		// Rule should be set for allowed requests
		if httpReq.MatchedRule != "allow-all" {
			t.Errorf("unexpected MatchedRule %v", httpReq.MatchedRule)
		}
	default:
		t.Fatal("expected log in channel, got none")
	}
}

func TestSocketAuditor_AuditRequest_AllowIncludesRule(t *testing.T) {
	t.Parallel()

	auditor := setupSocketAuditor(t)

	auditor.AuditRequest(Request{
		Method:  "POST",
		URL:     "https://evil.com",
		Host:    "evil.com",
		Allowed: true,
		Rule:    "allow-evil",
	})

	select {
	case log := <-auditor.logCh:
		if log.Allowed != true {
			t.Errorf("expected Allowed=false, got %v", log.Allowed)
		}
		httpReq := log.GetHttpRequest()
		if httpReq == nil {
			t.Fatal("expected HttpRequest, got nil")
		}
		if httpReq.MatchedRule != "allow-evil" {
			t.Errorf("expected MatchedRule=allow-evil, got %s", httpReq.MatchedRule)
		}
	default:
		t.Fatal("expected log in channel, got none")
	}
}

func TestSocketAuditor_AuditRequest_DropsWhenFull(t *testing.T) {
	t.Parallel()

	auditor := setupSocketAuditor(t)

	// Fill the audit log buffer.
	for i := 0; i < cap(auditor.logCh); i++ {
		auditor.AuditRequest(Request{Method: "GET", URL: "https://example.com", Allowed: true})
	}

	// This should not block and drop the log
	auditor.AuditRequest(Request{Method: "GET", URL: "https://dropped.com", Allowed: true})

	// Drain the channel and verify all entries are from the original batch (dropped.com was dropped)
	for i := 0; i < cap(auditor.logCh); i++ {
		v := <-auditor.logCh
		resource, ok := v.Resource.(*agentproto.BoundaryLog_HttpRequest_)
		if !ok {
			t.Fatal("unexpected resource type")
		}
		if resource.HttpRequest.Url != "https://example.com" {
			t.Errorf("expected batch to be FIFO, got %s", resource.HttpRequest.Url)
		}
	}

	select {
	case v := <-auditor.logCh:
		t.Errorf("expected empty channel, got %v", v)
	default:
	}
}

func TestSocketAuditor_Loop_FlushesOnBatchSize(t *testing.T) {
	t.Parallel()

	auditor, serverConn := setupTestAuditor(t)
	auditor.batchTimerDuration = time.Hour // Ensure timer doesn't interfere with the test

	cr := newConnReader()
	go readFromConn(t, serverConn, cr)

	go auditor.Loop(t.Context())

	// Send exactly a full batch of logs to trigger a flush
	for i := 0; i < cap(auditor.logCh); i++ {
		auditor.AuditRequest(Request{Method: "GET", URL: "https://example.com", Allowed: true})
	}

	select {
	case req := <-cr.logs:
		if len(req.Logs) != auditor.batchSize {
			t.Errorf("expected %d logs, got %d", auditor.batchSize, len(req.Logs))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for flush")
	}
}

func TestSocketAuditor_Loop_FlushesOnTimer(t *testing.T) {
	t.Parallel()

	auditor, serverConn := setupTestAuditor(t)
	auditor.batchTimerDuration = 3 * time.Second

	cr := newConnReader()
	go readFromConn(t, serverConn, cr)

	go auditor.Loop(t.Context())

	// A single log should start the timer
	auditor.AuditRequest(Request{Method: "GET", URL: "https://example.com", Allowed: true})

	// Should flush after the timer duration elapses
	select {
	case req := <-cr.logs:
		if len(req.Logs) != 1 {
			t.Errorf("expected 1 log, got %d", len(req.Logs))
		}
	case <-time.After(2 * auditor.batchTimerDuration):
		t.Fatal("timeout waiting for timer flush")
	}
}

func TestSocketAuditor_Loop_FlushesOnContextCancel(t *testing.T) {
	t.Parallel()

	auditor, serverConn := setupTestAuditor(t)
	// Make the timer long to always exercise the context cancellation case
	auditor.batchTimerDuration = time.Hour

	cr := newConnReader()
	go readFromConn(t, serverConn, cr)

	ctx, cancel := context.WithCancel(t.Context())

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		auditor.Loop(ctx)
	}()

	// Send a log but don't fill the batch
	auditor.AuditRequest(Request{Method: "GET", URL: "https://example.com", Allowed: true})

	cancel()

	select {
	case req := <-cr.logs:
		if len(req.Logs) != 1 {
			t.Errorf("expected 1 log, got %d", len(req.Logs))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for shutdown flush")
	}

	wg.Wait()
}

func TestSocketAuditor_Loop_RetriesOnConnectionFailure(t *testing.T) {
	t.Parallel()

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		err := clientConn.Close()
		if err != nil {
			t.Errorf("close client connection: %v", err)
		}
		err = serverConn.Close()
		if err != nil {
			t.Errorf("close server connection: %v", err)
		}
	})

	var dialCount atomic.Int32
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	auditor := &SocketAuditor{
		dial: func() (net.Conn, error) {
			// First dial attempt fails, subsequent ones succeed
			if dialCount.Add(1) == 1 {
				return nil, errors.New("connection refused")
			}
			return clientConn, nil
		},
		logger:             logger,
		logCh:              make(chan *agentproto.BoundaryLog, 2*defaultBatchSize),
		batchSize:          defaultBatchSize,
		batchTimerDuration: time.Hour, // Ensure timer doesn't interfere with the test
		sessionID:          "test-session-id",
		seq:                &SequenceCounter{},
	}

	// Set up hook to detect flush attempts
	flushed := make(chan struct{}, 1)
	auditor.onFlushAttempt = func() {
		select {
		case flushed <- struct{}{}:
		default:
		}
	}

	cr := newConnReader()
	go readFromConn(t, serverConn, cr)

	go auditor.Loop(t.Context())

	// Send batchSize+1 logs so we can verify the last log here gets dropped.
	for i := 0; i < auditor.batchSize+1; i++ {
		auditor.AuditRequest(Request{Method: "GET", URL: "https://servernotup.com", Allowed: true})
	}

	// Wait for the first flush attempt (which will fail)
	select {
	case <-flushed:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for first flush attempt")
	}

	// Send one more log - batch is at capacity, so this triggers flush first
	// The flush succeeds (dial now works), sending the retained batch.
	auditor.AuditRequest(Request{Method: "POST", URL: "https://serverup.com", Allowed: true})

	// Should receive the retained batch (the new log goes into a fresh batch)
	select {
	case req := <-cr.logs:
		if len(req.Logs) != auditor.batchSize {
			t.Errorf("expected %d logs from retry, got %d", auditor.batchSize, len(req.Logs))
		}
		for _, log := range req.Logs {
			resource, ok := log.Resource.(*agentproto.BoundaryLog_HttpRequest_)
			if !ok {
				t.Fatal("unexpected resource type")
			}
			if resource.HttpRequest.Url != "https://servernotup.com" {
				t.Errorf("expected URL https://servernotup.com, got %v", resource.HttpRequest.Url)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for retry flush")
	}
}

func TestSocketAuditor_Loop_ReportsChannelFullDrops(t *testing.T) {
	t.Parallel()

	auditor, serverConn := setupTestAuditor(t)
	auditor.batchTimerDuration = time.Hour

	cr := newConnReader()
	go readFromConn(t, serverConn, cr)

	// Fill the channel to capacity before starting the loop so the
	// drop is deterministic.
	for i := 0; i < cap(auditor.logCh); i++ {
		auditor.AuditRequest(Request{Method: "GET", URL: "https://example.com", Allowed: true})
	}

	// This one should be dropped (channel full).
	auditor.AuditRequest(Request{Method: "GET", URL: "https://dropped.com", Allowed: true})

	// Start the loop. The drop counter is already set, so the first
	// successful flush will be followed by a BoundaryStatus message.
	go auditor.Loop(t.Context())

	// Drain log batches first.
	for i := 0; i < cap(auditor.logCh)/auditor.batchSize; i++ {
		select {
		case <-cr.logs:
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for log flush")
		}
	}

	// The status message should arrive after the first successful flush.
	select {
	case status := <-cr.status:
		if status.DroppedChannelFull != 1 {
			t.Errorf("expected DroppedChannelFull=1, got %d", status.DroppedChannelFull)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for BoundaryStatus")
	}
}

func TestSocketAuditor_Loop_ReportsBatchFullDrops(t *testing.T) {
	t.Parallel()

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	var dialCount atomic.Int32
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	auditor := &SocketAuditor{
		dial: func() (net.Conn, error) {
			// First 3 dials fail: initial connect, first doFlush
			// (batch full), second doFlush (causes batch-full drop).
			// Dial 4 succeeds and carries the drop status.
			if dialCount.Add(1) <= 3 {
				return nil, errors.New("connection refused")
			}
			return clientConn, nil
		},
		logger:             logger,
		logCh:              make(chan *agentproto.BoundaryLog, 2*defaultBatchSize),
		batchSize:          defaultBatchSize,
		batchTimerDuration: time.Hour,
		sessionID:          "test-session-id",
		seq:                &SequenceCounter{},
	}

	flushed := make(chan struct{}, 4)
	auditor.onFlushAttempt = func() {
		select {
		case flushed <- struct{}{}:
		default:
		}
	}

	cr := newConnReader()
	go readFromConn(t, serverConn, cr)

	go auditor.Loop(t.Context())

	// Send batchSize+1 logs. The batch fills and doFlush fails (dial 2).
	// The +1 log triggers another doFlush that also fails (dial 3),
	// so the log is dropped as batch-full.
	for i := 0; i < auditor.batchSize+1; i++ {
		auditor.AuditRequest(Request{Method: "GET", URL: "https://example.com", Allowed: true})
	}

	// Wait for 2 failed flush attempts.
	for i := 0; i < 2; i++ {
		select {
		case <-flushed:
		case <-time.After(5 * time.Second):
			t.Fatalf("timeout waiting for flush attempt %d", i+1)
		}
	}

	// Send another log to trigger a successful flush (dial 4).
	auditor.AuditRequest(Request{Method: "GET", URL: "https://retry.com", Allowed: true})

	// The successful flush sends logs first, then a status message.
	select {
	case <-cr.logs:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for retry flush")
	}

	select {
	case status := <-cr.status:
		if status.DroppedBatchFull != 1 {
			t.Errorf("expected DroppedBatchFull=1, got %d", status.DroppedBatchFull)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for BoundaryStatus")
	}
}

func TestSocketAuditor_Loop_ShutdownFlushIncludesDrops(t *testing.T) {
	t.Parallel()

	auditor, serverConn := setupTestAuditor(t)
	auditor.batchTimerDuration = time.Hour

	cr := newConnReader()
	go readFromConn(t, serverConn, cr)

	ctx, cancel := context.WithCancel(t.Context())

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		auditor.Loop(ctx)
	}()

	// Simulate drops that haven't been flushed yet.
	auditor.droppedChannelFull.Store(3)
	auditor.droppedBatchFull.Store(2)

	// Send one log so the shutdown flush has something to send.
	auditor.AuditRequest(Request{Method: "GET", URL: "https://example.com", Allowed: true})

	cancel()
	wg.Wait()

	// Shutdown flush sends logs then status.
	select {
	case <-cr.logs:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for shutdown flush logs")
	}

	select {
	case status := <-cr.status:
		if status.DroppedChannelFull != 3 {
			t.Errorf("expected DroppedChannelFull=3, got %d", status.DroppedChannelFull)
		}
		if status.DroppedBatchFull != 2 {
			t.Errorf("expected DroppedBatchFull=2, got %d", status.DroppedBatchFull)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for BoundaryStatus in shutdown flush")
	}
}

func TestFlush_EmptyBatch(t *testing.T) {
	t.Parallel()

	err := flush(nil, "", nil)
	if err != nil {
		t.Errorf("expected nil error for empty batch, got %v", err)
	}

	err = flush(nil, "", []*agentproto.BoundaryLog{})
	if err != nil {
		t.Errorf("expected nil error for empty slice, got %v", err)
	}
}

func TestSocketAuditor_AuditRequest_SequenceNumberIncrements(t *testing.T) {
	t.Parallel()

	auditor := setupSocketAuditor(t)

	for i := range 5 {
		auditor.AuditRequest(Request{Method: "GET", URL: "https://example.com", Allowed: true})

		select {
		case log := <-auditor.logCh:
			if log.SequenceNumber != uint64(i) {
				t.Errorf("request %d: expected SequenceNumber=%d, got %d", i, i, log.SequenceNumber)
			}
		default:
			t.Fatalf("request %d: expected log in channel, got none", i)
		}
	}
}

func TestSocketAuditor_Loop_FlushIncludesSessionID(t *testing.T) {
	t.Parallel()

	auditor, serverConn := setupTestAuditor(t)
	auditor.batchTimerDuration = time.Hour

	cr := newConnReader()
	go readFromConn(t, serverConn, cr)

	go auditor.Loop(t.Context())

	// Fill a batch to trigger a flush.
	for i := 0; i < auditor.batchSize; i++ {
		auditor.AuditRequest(Request{Method: "GET", URL: "https://example.com", Allowed: true})
	}

	select {
	case req := <-cr.logs:
		if req.SessionId != "test-session-id" {
			t.Errorf("expected SessionId=test-session-id, got %q", req.SessionId)
		}
		if len(req.Logs) != auditor.batchSize {
			t.Errorf("expected %d logs, got %d", auditor.batchSize, len(req.Logs))
		}
		// Verify sequence numbers are monotonically increasing.
		for i, log := range req.Logs {
			if log.SequenceNumber != uint64(i) {
				t.Errorf("log %d: expected SequenceNumber=%d, got %d", i, i, log.SequenceNumber)
			}
			if log.Time == nil {
				t.Errorf("log %d: expected Time to be set", i)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for flush")
	}
}

// setupSocketAuditor creates a SocketAuditor for tests that only exercise
// the queueing behavior (no connection needed).
func setupSocketAuditor(t *testing.T) *SocketAuditor {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &SocketAuditor{
		dial: func() (net.Conn, error) {
			return nil, errors.New("not connected")
		},
		logger:             logger,
		logCh:              make(chan *agentproto.BoundaryLog, 2*defaultBatchSize),
		batchSize:          defaultBatchSize,
		batchTimerDuration: defaultBatchTimerDuration,
		sessionID:          "test-session-id",
		seq:                &SequenceCounter{},
	}
}

// setupTestAuditor creates a SocketAuditor with an in-memory connection using
// net.Pipe(). Returns the auditor and the server-side connection for reading.
func setupTestAuditor(t *testing.T) (*SocketAuditor, net.Conn) {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		err := clientConn.Close()
		if err != nil {
			t.Error("Failed to close client connection", "error", err)
		}
		err = serverConn.Close()
		if err != nil {
			t.Error("Failed to close server connection", "error", err)
		}
	})

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	auditor := &SocketAuditor{
		dial: func() (net.Conn, error) {
			return clientConn, nil
		},
		logger:             logger,
		logCh:              make(chan *agentproto.BoundaryLog, 2*defaultBatchSize),
		batchSize:          defaultBatchSize,
		batchTimerDuration: defaultBatchTimerDuration,
		sessionID:          "test-session-id",
		seq:                &SequenceCounter{},
	}

	return auditor, serverConn
}

// connReader holds channels for dispatching decoded messages from a
// boundary socket connection.
type connReader struct {
	logs   chan *agentproto.ReportBoundaryLogsRequest
	status chan *codec.BoundaryStatus
}

func newConnReader() *connReader {
	return &connReader{
		logs:   make(chan *agentproto.ReportBoundaryLogsRequest, 8),
		status: make(chan *codec.BoundaryStatus, 8),
	}
}

// readFromConn reads TagV2 BoundaryMessage envelopes from a connection and
// dispatches them to the appropriate channel.
func readFromConn(t *testing.T, conn net.Conn, r *connReader) {
	t.Helper()

	buf := make([]byte, 1<<10)
	for {
		msg, newBuf, err := codec.ReadMessage(conn, buf)
		if err != nil {
			return // connection closed
		}
		buf = newBuf

		switch m := msg.(type) {
		case *codec.BoundaryMessage:
			switch inner := m.Msg.(type) {
			case *codec.BoundaryMessage_Logs:
				r.logs <- inner.Logs
			case *codec.BoundaryMessage_Status:
				r.status <- inner.Status
			default:
				t.Errorf("unexpected BoundaryMessage variant: %T", inner)
			}
		default:
			t.Errorf("unexpected message type: %T", msg)
		}
	}
}
