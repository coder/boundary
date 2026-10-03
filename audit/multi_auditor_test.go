package audit

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/coder/coder/v2/agent/boundarylogproxy/codec"
)

type mockAuditor struct {
	onAudit func(req Request)
}

func (m *mockAuditor) AuditRequest(req Request) {
	if m.onAudit != nil {
		m.onAudit(req)
	}
}

func TestSetupAuditor_DisabledAuditLogs(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()

	auditor, closeAuditor, err := SetupAuditor(ctx, logger, true, "", uuid.New(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Without a socket auditor there is nothing to flush.
	closeAuditor()

	multi, ok := auditor.(*MultiAuditor)
	if !ok {
		t.Fatalf("expected *MultiAuditor, got %T", auditor)
	}

	if len(multi.auditors) != 1 {
		t.Errorf("expected 1 auditor, got %d", len(multi.auditors))
	}

	if _, ok := multi.auditors[0].(*LogAuditor); !ok {
		t.Errorf("expected *LogAuditor, got %T", multi.auditors[0])
	}
}

func TestSetupAuditor_EmptySocketPath(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()

	_, _, err := SetupAuditor(ctx, logger, false, "", uuid.New(), "")
	if err == nil {
		t.Fatal("expected error for empty socket path, got nil")
	}
}

func TestSetupAuditor_SocketDoesNotExist(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()

	auditor, _, err := SetupAuditor(ctx, logger, false, "/nonexistent/socket/path", uuid.New(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	multi, ok := auditor.(*MultiAuditor)
	if !ok {
		t.Fatalf("expected *MultiAuditor, got %T", auditor)
	}

	if len(multi.auditors) != 1 {
		t.Errorf("expected 1 auditor, got %d", len(multi.auditors))
	}

	if _, ok := multi.auditors[0].(*LogAuditor); !ok {
		t.Errorf("expected *LogAuditor, got %T", multi.auditors[0])
	}
}

func TestSetupAuditor_SocketExists(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create a temporary file to simulate the socket existing
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")
	f, err := os.Create(socketPath)
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	err = f.Close()
	if err != nil {
		t.Fatalf("failed to close temp file: %v", err)
	}

	auditor, _, err := SetupAuditor(ctx, logger, false, socketPath, uuid.New(), "claude")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	multi, ok := auditor.(*MultiAuditor)
	if !ok {
		t.Fatalf("expected *MultiAuditor, got %T", auditor)
	}

	if len(multi.auditors) != 2 {
		t.Errorf("expected 2 auditors, got %d", len(multi.auditors))
	}

	if _, ok := multi.auditors[0].(*LogAuditor); !ok {
		t.Errorf("expected first auditor to be *LogAuditor, got %T", multi.auditors[0])
	}

	if _, ok := multi.auditors[1].(*SocketAuditor); !ok {
		t.Errorf("expected second auditor to be *SocketAuditor, got %T", multi.auditors[1])
	}
}

func TestMultiAuditor_AuditRequest(t *testing.T) {
	t.Parallel()

	var called1, called2 bool
	auditor1 := &mockAuditor{onAudit: func(req Request) { called1 = true }}
	auditor2 := &mockAuditor{onAudit: func(req Request) { called2 = true }}

	multi := NewMultiAuditor(auditor1, auditor2)
	multi.AuditRequest(Request{Method: "GET", URL: "https://example.com"})

	if !called1 {
		t.Error("expected first auditor to be called")
	}
	if !called2 {
		t.Error("expected second auditor to be called")
	}
}

// TestSetupAuditor_CloseSendsQueuedLogs covers a wrapped command that exits
// right after a request: the log is still queued for the next batch, and
// close must send it to the workspace agent before returning.
func TestSetupAuditor_CloseSendsQueuedLogs(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(t.TempDir(), "agent.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to listen on unix socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	auditor, closeAuditor, err := SetupAuditor(t.Context(), logger, false, socketPath, uuid.New(), "claude")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// One request does not fill a batch, so without close it would wait for
	// the batch timer.
	auditor.AuditRequest(Request{Method: "GET", URL: "https://example.com/last", Allowed: true})
	closeAuditor()

	var conn net.Conn
	select {
	case conn = <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for the auditor to connect")
	}
	t.Cleanup(func() { _ = conn.Close() })

	// Close returns only after the batch is written, so it is already in the
	// socket buffer. The deadline only bounds the failure case.
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("failed to set read deadline: %v", err)
	}
	msg, _, err := codec.ReadMessage(conn, make([]byte, 1<<10))
	if err != nil {
		t.Fatalf("expected the queued log to be sent before close returned: %v", err)
	}
	boundaryMsg, ok := msg.(*codec.BoundaryMessage)
	if !ok {
		t.Fatalf("expected *codec.BoundaryMessage, got %T", msg)
	}
	logs := boundaryMsg.GetLogs().GetLogs()
	if len(logs) != 1 {
		t.Fatalf("expected 1 log, got %d", len(logs))
	}
	if got := logs[0].GetHttpRequest().GetUrl(); got != "https://example.com/last" {
		t.Errorf("expected URL https://example.com/last, got %s", got)
	}
}

// TestRunSocketAuditor_StopIsBoundedByContext verifies that an unresponsive
// workspace agent cannot block stop past its context deadline.
func TestRunSocketAuditor_StopIsBoundedByContext(t *testing.T) {
	t.Parallel()

	unblockDial := make(chan struct{})
	auditor := setupSocketAuditor(t)
	auditor.dial = func() (net.Conn, error) {
		<-unblockDial
		return nil, errors.New("agent not responding")
	}

	stop := runSocketAuditor(t.Context(), auditor)

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if err := stop(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}

	// Once the agent responds, the loop finishes and stop returns nil.
	close(unblockDial)
	waitCtx, waitCancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer waitCancel()
	if err := stop(waitCtx); err != nil {
		t.Fatalf("expected the loop to finish, got %v", err)
	}
}
