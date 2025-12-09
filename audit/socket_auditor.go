package audit

import (
	"encoding/binary"
	"net"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentproto "github.com/coder/coder/v2/agent/proto"
)

const (
	socketFlushInterval = 5 * time.Second
	socketBatchSize     = 10
)

// SocketAuditor implements the Auditor interface by sending logs to the
// workspace agent's boundary log proxy socket. It batches logs using either
// a 5-second timeout or when 10 logs have accumulated, whichever comes first.
type SocketAuditor struct {
	socketPath  string
	workspaceID []byte

	mu         sync.Mutex
	conn       net.Conn
	logs       []*agentproto.BoundaryLog
	closed     bool
	flushTimer *time.Timer
}

// NewSocketAuditor creates a new SocketAuditor that sends logs to the agent's
// boundary log proxy socket. The workspaceID should be the 16-byte UUID.
func NewSocketAuditor(socketPath string, workspaceID []byte) *SocketAuditor {
	return &SocketAuditor{
		socketPath:  socketPath,
		workspaceID: workspaceID,
	}
}

// AuditRequest implements the Auditor interface. It queues the request and
// batches sends to the agent socket.
func (s *SocketAuditor) AuditRequest(req Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return
	}

	log := &agentproto.BoundaryLog{
		WorkspaceId: s.workspaceID,
		Time:        timestamppb.Now(),
		Allowed:     req.Allowed,
		HttpMethod:  req.Method,
		HttpUrl:     req.URL,
		MatchedRule: req.Rule,
	}
	s.logs = append(s.logs, log)

	// Start flush timer if this is the first log.
	if len(s.logs) == 1 {
		s.flushTimer = time.AfterFunc(socketFlushInterval, func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.flushLocked()
		})
	}

	// Flush immediately if we've reached batch size.
	if len(s.logs) >= socketBatchSize {
		if s.flushTimer != nil {
			s.flushTimer.Stop()
			s.flushTimer = nil
		}
		s.flushLocked()
	}
}

// flushLocked sends the current batch of logs. Caller must hold the lock.
func (s *SocketAuditor) flushLocked() {
	if len(s.logs) == 0 {
		return
	}

	// Try to connect if not connected.
	if s.conn == nil {
		conn, err := net.Dial("unix", s.socketPath)
		if err != nil {
			// Drop logs if we can't connect.
			s.logs = nil
			return
		}
		s.conn = conn
	}

	req := &agentproto.ReportBoundaryLogsRequest{
		Logs: s.logs,
	}

	data, err := proto.Marshal(req)
	if err != nil {
		s.logs = nil
		return
	}

	// Write length-prefixed message.
	if err := binary.Write(s.conn, binary.BigEndian, uint32(len(data))); err != nil {
		// Connection error - close and try again next time.
		_ = s.conn.Close()
		s.conn = nil
		s.logs = nil
		return
	}
	if _, err := s.conn.Write(data); err != nil {
		_ = s.conn.Close()
		s.conn = nil
		s.logs = nil
		return
	}

	s.logs = nil
}

// Close flushes any remaining logs and closes the connection.
func (s *SocketAuditor) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.closed = true
	if s.flushTimer != nil {
		s.flushTimer.Stop()
		s.flushTimer = nil
	}

	s.flushLocked()

	if s.conn != nil {
		err := s.conn.Close()
		s.conn = nil
		return err
	}
	return nil
}
