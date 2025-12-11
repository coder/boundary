package audit

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentproto "github.com/coder/coder/v2/agent/proto"
)

const (
	defaultBatchSize          = 10
	defaultBatchTimerDuration = 5 * time.Second
	// DefaultAuditSocketPath is the well-known path for the boundary audit socket.
	// The expectation is the Coder agent listens on this socket to receive audit logs.
	DefaultAuditSocketPath = "/tmp/boundary-audit.sock"
)

// SocketAuditor implements the Auditor interface. It sends logs to the
// workspace agent's boundary log proxy socket. It queues logs and sends
// them in batches using a batch size and timer. The internal queue operates
// as a FIFO i.e., logs are sent in the order they are received and dropped
// if the queue is full.
//
// The proto messages sent to the agent are framed as follows:
// [4 bit tag][28 bit length][length bytes of encoded protobuf]
//
// The tag is currently always 1, but may be extended in the future (e.g.
// to support compression).
type SocketAuditor struct {
	socketPath         string
	logger             *slog.Logger
	logCh              chan *agentproto.BoundaryLog
	batchSize          int
	batchTimerDuration time.Duration

	// onFlushAttempt is called after each flush attempt (intended for testing).
	onFlushAttempt func()
}

// NewSocketAuditor creates a new SocketAuditor that sends logs to the agent's
// boundary log proxy socket at DefaultAuditSocketPath after SocketAuditor.Loop
// is called.
func NewSocketAuditor(logger *slog.Logger) *SocketAuditor {
	return &SocketAuditor{
		socketPath:         DefaultAuditSocketPath,
		logger:             logger,
		logCh:              make(chan *agentproto.BoundaryLog, 2*defaultBatchSize),
		batchSize:          defaultBatchSize,
		batchTimerDuration: defaultBatchTimerDuration,
	}
}

// AuditRequest implements the Auditor interface. It queues the log to be sent to the
// agent in a batch.
func (s *SocketAuditor) AuditRequest(req Request) {
	httpReq := &agentproto.BoundaryLog_HttpRequest{
		Method: req.Method,
		Url:    req.URL,
	}
	// Only include the matched rule for allowed requests. Boundary is deny by
	// default, so rules are what allow requests.
	if req.Allowed {
		httpReq.MatchedRule = req.Rule
	}

	log := &agentproto.BoundaryLog{
		Allowed:  req.Allowed,
		Time:     timestamppb.Now(),
		Resource: &agentproto.BoundaryLog_HttpRequest_{HttpRequest: httpReq},
	}

	select {
	case s.logCh <- log:
	default:
		s.logger.Warn("audit log dropped, channel full")
	}
}

// flushErr represents an error from flush, distinguishing between
// permanent errors (bad data) and transient errors (network issues).
type flushErr struct {
	err       error
	permanent bool
}

func (e *flushErr) Error() string { return e.err.Error() }

// flush sends the current batch of logs to the given connection.
func flush(conn net.Conn, logs []*agentproto.BoundaryLog) *flushErr {
	if len(logs) == 0 {
		return nil
	}

	req := &agentproto.ReportBoundaryLogsRequest{
		Logs: logs,
	}

	data, err := proto.Marshal(req)
	if err != nil {
		return &flushErr{err: err, permanent: true}
	}

	if len(data) > 1<<28 {
		return &flushErr{err: fmt.Errorf("data too large: %d bytes", len(data)), permanent: true}
	}

	var header uint32
	header |= uint32(len(data))
	header |= 1 << 28

	if err := binary.Write(conn, binary.BigEndian, header); err != nil {
		return &flushErr{err: err}
	}
	if _, err := conn.Write(data); err != nil {
		return &flushErr{err: err}
	}
	return nil
}

// Loop handles the I/O to send audit logs to the agent.
func (s *SocketAuditor) Loop(ctx context.Context) {
	var conn net.Conn
	batch := make([]*agentproto.BoundaryLog, 0, s.batchSize)
	t := time.NewTimer(0)
	t.Stop()

	// connect attempts to establish a connection to the socket.
	connect := func() {
		if conn != nil {
			return
		}
		var err error
		conn, err = net.Dial("unix", s.socketPath)
		if err != nil {
			s.logger.Warn("failed to connect to audit socket", "path", s.socketPath, "error", err)
			conn = nil
		}
	}

	// closeConn closes the current connection if open.
	closeConn := func() {
		if conn != nil {
			_ = conn.Close()
			conn = nil
		}
	}

	// clearBatch resets the length of the batch and frees memory while preserving
	// the batch slice backing array.
	clearBatch := func() {
		for i := range len(batch) {
			batch[i] = nil
		}
		batch = batch[:0]
	}

	// doFlush flushes the batch and handles errors by reconnecting.
	doFlush := func() {
		t.Stop()
		defer func() {
			if s.onFlushAttempt != nil {
				s.onFlushAttempt()
			}
		}()
		if len(batch) == 0 {
			return
		}
		connect()
		if conn == nil {
			// No connection: logs will be retried on next flush.
			return
		}

		if err := flush(conn, batch); err != nil {
			s.logger.Warn("failed to flush audit logs", "error", err)
			if err.permanent {
				// Data error: discard batch to avoid infinite retries.
				clearBatch()
			} else {
				// Network error: close connection but keep batch for a future retry.
				closeConn()
			}
			return
		}

		clearBatch()
	}

	connect()

	for {
		select {
		case <-ctx.Done():
			// Drain any pending logs before the last flush. Not concerned about
			// growing the batch slice here since we're exiting.
		drain:
			for {
				select {
				case log := <-s.logCh:
					batch = append(batch, log)
				default:
					break drain
				}
			}

			doFlush()
			closeConn()
			return
		case <-t.C:
			doFlush()
		case log := <-s.logCh:
			// If batch is at capacity, attempt flushing first and drop the log if
			// the batch still full.
			if len(batch) >= s.batchSize {
				doFlush()
				if len(batch) >= s.batchSize {
					s.logger.Warn("audit log dropped, batch full")
					continue
				}
			}

			batch = append(batch, log)

			if len(batch) == 1 {
				t.Reset(s.batchTimerDuration)
			}

			if len(batch) >= s.batchSize {
				doFlush()
			}
		}
	}
}
