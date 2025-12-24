package audit

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

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

	// Fill the channel (capacity is 2*batchSize = 20)
	for i := 0; i < 2*auditor.batchSize; i++ {
		auditor.AuditRequest(Request{Method: "GET", URL: "https://example.com", Allowed: true})
	}

	// This should not block and drop the log
	auditor.AuditRequest(Request{Method: "GET", URL: "https://dropped.com", Allowed: true})

	// Drain the channel and verify all entries are from the original batch (dropped.com was dropped)
	for i := 0; i < 2*auditor.batchSize; i++ {
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

	auditor := setupSocketAuditor(t)
	auditor.batchTimerDuration = time.Hour // Ensure timer doesn't interfere with the test
	received := make(chan *agentproto.ReportBoundaryLogsRequest, 1)
	startTestServer(t, auditor.socketPath, received)

	go auditor.Loop(t.Context())

	// Send exactly a full batch of logs to trigger a flush
	for i := 0; i < auditor.batchSize; i++ {
		auditor.AuditRequest(Request{Method: "GET", URL: "https://example.com", Allowed: true})
	}

	select {
	case req := <-received:
		if len(req.Logs) != auditor.batchSize {
			t.Errorf("expected %d logs, got %d", auditor.batchSize, len(req.Logs))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for flush")
	}
}

func TestSocketAuditor_Loop_FlushesOnTimer(t *testing.T) {
	t.Parallel()

	auditor := setupSocketAuditor(t)
	auditor.batchTimerDuration = 3 * time.Second
	received := make(chan *agentproto.ReportBoundaryLogsRequest, 1)
	startTestServer(t, auditor.socketPath, received)

	go auditor.Loop(t.Context())

	// A single log should start the timer
	auditor.AuditRequest(Request{Method: "GET", URL: "https://example.com", Allowed: true})

	// Should flush after the timer duration elapses
	select {
	case req := <-received:
		if len(req.Logs) != 1 {
			t.Errorf("expected 1 log, got %d", len(req.Logs))
		}
	case <-time.After(2 * auditor.batchTimerDuration):
		t.Fatal("timeout waiting for timer flush")
	}
}

func TestSocketAuditor_Loop_FlushesOnContextCancel(t *testing.T) {
	t.Parallel()

	received := make(chan *agentproto.ReportBoundaryLogsRequest, 1)

	auditor := setupSocketAuditor(t)
	// Make the timer long to always exercise the context cancellation case
	auditor.batchTimerDuration = time.Hour
	startTestServer(t, auditor.socketPath, received)

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
	case req := <-received:
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

	// Don't start server yet because we want the connection to fail
	auditor := setupSocketAuditor(t)
	auditor.batchTimerDuration = time.Hour // Ensure timer doesn't interfere with the test
	socketPath := auditor.socketPath

	// Set up hook to detect flush attempts
	flushed := make(chan struct{}, 1)
	auditor.onFlushAttempt = func() {
		select {
		case flushed <- struct{}{}:
		default:
		}
	}

	go auditor.Loop(t.Context())

	// Send batchSize+1 logs so we can verify the last log here gets dropped.
	for i := 0; i < auditor.batchSize+1; i++ {
		url := "https://servernotup" + strconv.Itoa(i) + ".com"
		auditor.AuditRequest(Request{Method: "GET", URL: url, Allowed: true})
	}

	// Wait for the first flush attempt before starting the server
	select {
	case <-flushed:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for first flush attempt")
	}

	// Now start the server
	received := make(chan *agentproto.ReportBoundaryLogsRequest, 1)
	startTestServer(t, socketPath, received)

	// Send one more log - batch is at capacity, so this triggers flush first
	// The flush succeeds (server is up), sending the retained batch.
	auditor.AuditRequest(Request{Method: "POST", URL: "https://serverup.com", Allowed: true})

	// Should receive the retained batch (the new log goes into a fresh batch)
	select {
	case req := <-received:
		if len(req.Logs) != auditor.batchSize {
			t.Errorf("expected %d logs from retry, got %d", auditor.batchSize, len(req.Logs))
		}
		for i, log := range req.Logs {
			resource, ok := log.Resource.(*agentproto.BoundaryLog_HttpRequest_)
			if !ok {
				t.Fatal("unexpected resource type")
			}
			expected := "https://servernotup" + strconv.Itoa(i) + ".com"
			if resource.HttpRequest.Url != expected {
				t.Errorf("expected log %d URL %s got %v", i, expected, resource.HttpRequest.Url)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for retry flush")
	}

	// Trigger another batch and verify contents
	for i := 0; i < auditor.batchSize-1; i++ {
		url := "https://secondbatch" + strconv.Itoa(i) + ".com"
		auditor.AuditRequest(Request{Method: "GET", URL: url, Allowed: true})
	}

	select {
	case req := <-received:
		if len(req.Logs) != auditor.batchSize {
			t.Errorf("expected %d logs from retry, got %d", auditor.batchSize, len(req.Logs))
		}
		for i, log := range req.Logs {
			resource, ok := log.Resource.(*agentproto.BoundaryLog_HttpRequest_)
			if !ok {
				t.Fatal("unexpected resource type")
			}
			expected := "https://secondbatch" + strconv.Itoa(i-1) + ".com"
			if i == 0 {
				expected = "https://serverup.com"
			}
			if resource.HttpRequest.Url != expected {
				t.Errorf("expected log %d URL %s got %v", i, expected, resource.HttpRequest.Url)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for flush")
	}
}

func TestFlush_EmptyBatch(t *testing.T) {
	t.Parallel()

	err := flush(nil, nil)
	if err != nil {
		t.Errorf("expected nil error for empty batch, got %v", err)
	}

	err = flush(nil, []*agentproto.BoundaryLog{})
	if err != nil {
		t.Errorf("expected nil error for empty slice, got %v", err)
	}
}

// tempDirUnixSocket returns a temporary directory that can safely hold unix
// sockets (probably).
//
// During tests on darwin we hit the max path length limit for unix sockets
// pretty easily in the default location, so this function uses /tmp instead to
// get shorter paths.
func tempDirUnixSocket(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "darwin" {
		testName := strings.ReplaceAll(t.Name(), "/", "_")
		dir, err := os.MkdirTemp("/tmp", testName)
		if err != nil {
			t.Errorf("failed to create temp dir: %v", err)
		}

		t.Cleanup(func() {
			err := os.RemoveAll(dir)
			if err != nil {
				t.Fatalf("remove temp dir %s: %v", dir, err)
			}
		})
		return dir
	}

	return t.TempDir()
}

func setupSocketAuditor(t *testing.T) *SocketAuditor {
	socketPath := path.Join(tempDirUnixSocket(t), "server.sock")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &SocketAuditor{
		socketPath:         socketPath,
		logger:             logger,
		logCh:              make(chan *agentproto.BoundaryLog, 2*defaultBatchSize),
		batchSize:          defaultBatchSize,
		batchTimerDuration: defaultBatchTimerDuration,
	}
}

// startTestServer starts a Unix socket server that reads length-prefixed protobuf messages,
// and reports all received requests to the given channel.
func startTestServer(t *testing.T, socketPath string, received chan<- *agentproto.ReportBoundaryLogsRequest) {
	t.Helper()

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to listen on socket: %v", err)
	}

	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = listener.Close()
		wg.Wait()
	})

	wg.Add(1)
	go func() {
		defer wg.Done()

		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			wg.Add(1)
			go handleConn(t, conn, &wg, received)
		}
	}()
}

func handleConn(t *testing.T, c net.Conn, wg *sync.WaitGroup, received chan<- *agentproto.ReportBoundaryLogsRequest) {
	t.Helper()
	defer wg.Done()
	defer func() { _ = c.Close() }()

	for {
		var header uint32
		if err := binary.Read(c, binary.BigEndian, &header); err != nil {
			return
		}

		length := header & 0x0FFFFFFF
		tag := header >> 28

		if tag != 1 {
			t.Errorf("invalid tag: %d", tag)
		}

		// Length could be larger but practically should be much smaller.
		// This is a sanity check.
		if length > 1<<15 {
			t.Errorf("invalid length: %d", header)
			return
		}

		data := make([]byte, length)
		if _, err := io.ReadFull(c, data); err != nil {
			t.Errorf("failed to read: %v", err)
			return
		}

		var req agentproto.ReportBoundaryLogsRequest
		if err := proto.Unmarshal(data, &req); err != nil {
			t.Errorf("failed to unmarshal: %v", err)
			return
		}

		received <- &req
	}
}
