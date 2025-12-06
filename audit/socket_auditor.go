package audit

import (
	"encoding/json"
	"log/slog"
	"net"
	"sync"
	"time"
)

const (
	// DefaultBatchSize is the maximum number of events to batch before sending.
	DefaultBatchSize = 10
	// DefaultFlushInterval is the maximum time to wait before sending a batch.
	DefaultFlushInterval = 10 * time.Second
)

// SocketEvent represents an audit event sent over the socket.
// This matches the format expected by the Coder agent.
type SocketEvent struct {
	Timestamp    time.Time `json:"timestamp"`
	ResourceType string    `json:"resource_type"` // "network", "file", etc.
	Resource     string    `json:"resource"`      // URL, file path, etc.
	Operation    string    `json:"operation"`     // "GET", "POST", "CONNECT", etc.
	Decision     string    `json:"decision"`      // "allow" or "deny"
}

// SocketAuditor implements Auditor by sending events to a Unix socket.
// It batches events and sends them when the batch is full or after a timeout.
type SocketAuditor struct {
	logger        *slog.Logger
	socketPath    string
	batchSize     int
	flushInterval time.Duration

	mu      sync.Mutex
	batch   []SocketEvent
	conn    net.Conn
	timer   *time.Timer
	closed  bool
	closeCh chan struct{}
}

// SocketAuditorConfig holds configuration for SocketAuditor.
type SocketAuditorConfig struct {
	Logger        *slog.Logger
	SocketPath    string
	BatchSize     int
	FlushInterval time.Duration
}

// NewSocketAuditor creates a new SocketAuditor.
func NewSocketAuditor(config SocketAuditorConfig) *SocketAuditor {
	batchSize := config.BatchSize
	if batchSize <= 0 {
		batchSize = DefaultBatchSize
	}
	flushInterval := config.FlushInterval
	if flushInterval <= 0 {
		flushInterval = DefaultFlushInterval
	}

	a := &SocketAuditor{
		logger:        config.Logger,
		socketPath:    config.SocketPath,
		batchSize:     batchSize,
		flushInterval: flushInterval,
		batch:         make([]SocketEvent, 0, batchSize),
		closeCh:       make(chan struct{}),
	}

	return a
}

// AuditRequest queues a request for batched sending.
func (a *SocketAuditor) AuditRequest(req Request) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.closed {
		return
	}

	decision := "deny"
	if req.Allowed {
		decision = "allow"
	}

	event := SocketEvent{
		Timestamp:    time.Now(),
		ResourceType: "network",
		Resource:     req.URL,
		Operation:    req.Method,
		Decision:     decision,
	}

	a.batch = append(a.batch, event)

	// Start timer on first event in batch.
	if len(a.batch) == 1 {
		a.timer = time.AfterFunc(a.flushInterval, func() {
			a.mu.Lock()
			defer a.mu.Unlock()
			a.flushLocked()
		})
	}

	// Flush if batch is full.
	if len(a.batch) >= a.batchSize {
		a.flushLocked()
	}
}

// flushLocked sends the current batch to the socket. Must be called with mu held.
func (a *SocketAuditor) flushLocked() {
	if len(a.batch) == 0 {
		return
	}

	// Stop the timer if running.
	if a.timer != nil {
		a.timer.Stop()
		a.timer = nil
	}

	// Copy batch and reset.
	events := make([]SocketEvent, len(a.batch))
	copy(events, a.batch)
	a.batch = a.batch[:0]

	// Send in background to not block.
	go a.sendEvents(events)
}

// sendEvents sends events to the socket.
func (a *SocketAuditor) sendEvents(events []SocketEvent) {
	// Connect if not connected.
	conn, err := a.getConnection()
	if err != nil {
		a.logger.Warn("failed to connect to audit socket", "error", err, "path", a.socketPath)
		return
	}

	// Marshal events as JSON array.
	data, err := json.Marshal(events)
	if err != nil {
		a.logger.Warn("failed to marshal audit events", "error", err)
		return
	}

	// Append newline as delimiter.
	data = append(data, '\n')

	// Write to socket.
	_, err = conn.Write(data)
	if err != nil {
		a.logger.Warn("failed to write to audit socket", "error", err)
		// Close connection on error so we reconnect next time.
		a.mu.Lock()
		if a.conn != nil {
			_ = a.conn.Close()
			a.conn = nil
		}
		a.mu.Unlock()
		return
	}

	a.logger.Debug("sent audit events", "count", len(events))
}

// getConnection returns an existing connection or creates a new one.
func (a *SocketAuditor) getConnection() (net.Conn, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.conn != nil {
		return a.conn, nil
	}

	conn, err := net.Dial("unix", a.socketPath)
	if err != nil {
		return nil, err
	}

	a.conn = conn
	return conn, nil
}

// Close flushes any remaining events and closes the connection.
func (a *SocketAuditor) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.closed {
		return nil
	}
	a.closed = true

	// Flush remaining events.
	if len(a.batch) > 0 {
		events := make([]SocketEvent, len(a.batch))
		copy(events, a.batch)
		a.batch = nil

		// Send synchronously on close.
		if a.conn != nil {
			data, err := json.Marshal(events)
			if err == nil {
				data = append(data, '\n')
				_, _ = a.conn.Write(data)
			}
		}
	}

	if a.timer != nil {
		a.timer.Stop()
	}

	if a.conn != nil {
		return a.conn.Close()
	}

	return nil
}
