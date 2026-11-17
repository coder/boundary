package audit

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/google/uuid"
)

// closeTimeout bounds how long the close function returned by SetupAuditor
// waits for pending audit logs to reach the workspace agent, so an
// unresponsive agent cannot block boundary from exiting.
const closeTimeout = 5 * time.Second

// MultiAuditor wraps multiple auditors and sends audit events to all of them.
type MultiAuditor struct {
	auditors []Auditor
}

// NewMultiAuditor creates a new MultiAuditor that sends to all provided auditors.
func NewMultiAuditor(auditors ...Auditor) *MultiAuditor {
	return &MultiAuditor{auditors: auditors}
}

// AuditRequest sends the request to all wrapped auditors.
func (m *MultiAuditor) AuditRequest(req Request) {
	for _, a := range m.auditors {
		a.AuditRequest(req)
	}
}

// SetupAuditor creates and configures the appropriate auditors based on the
// provided configuration. It always includes a LogAuditor for stderr logging,
// and conditionally adds a SocketAuditor if audit logs are enabled and the
// workspace agent's log proxy socket exists.
//
// The returned close function stops the SocketAuditor and waits up to
// closeTimeout for it to send logs that are still queued. Call it once the
// proxy has stopped producing audit events and before the process exits;
// otherwise logs from the last batch window never reach coderd.
func SetupAuditor(ctx context.Context, logger *slog.Logger, disableAuditLogs bool, logProxySocketPath string, sessionID uuid.UUID, confinedProcessName string) (Auditor, func(), error) {
	stderrAuditor := NewLogAuditor(logger)
	auditors := []Auditor{stderrAuditor}
	closeAuditor := func() {}

	if !disableAuditLogs {
		if logProxySocketPath == "" {
			return nil, nil, fmt.Errorf("log proxy socket path is undefined")
		}
		// Since boundary is separately versioned from a Coder deployment, it's possible
		// Coder is on an older version that will not create the socket and listen for
		// the audit logs. Here we check for the socket to determine if the workspace
		// agent is on a new enough version to prevent boundary application log spam from
		// trying to connect to the agent. This assumes the agent will run and start the
		// log proxy server before boundary runs.
		_, err := os.Stat(logProxySocketPath)
		if err != nil && !os.IsNotExist(err) {
			return nil, nil, fmt.Errorf("failed to stat log proxy socket: %v", err)
		}
		agentWillProxy := !os.IsNotExist(err)
		if agentWillProxy {
			socketAuditor := NewSocketAuditor(logger, logProxySocketPath, sessionID, confinedProcessName)
			stop := runSocketAuditor(ctx, socketAuditor)
			closeAuditor = func() {
				// The caller's context may already be canceled at exit, so
				// the wait gets its own deadline.
				waitCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), closeTimeout)
				defer cancel()
				if err := stop(waitCtx); err != nil {
					logger.Warn("Audit logs may not have been sent to the workspace agent before exit", "error", err)
				}
			}
			auditors = append(auditors, socketAuditor)
		} else {
			logger.Warn("Audit logs are disabled; workspace agent has not created log proxy socket",
				"socket", logProxySocketPath)
		}
	} else {
		logger.Warn("Audit logs are disabled by configuration")
	}

	return NewMultiAuditor(auditors...), closeAuditor, nil
}

// runSocketAuditor runs s.Loop in the background and returns a function that
// stops the loop and waits until it has flushed pending logs, or until waitCtx
// is done.
func runSocketAuditor(ctx context.Context, s *SocketAuditor) func(waitCtx context.Context) error {
	loopCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Loop(loopCtx)
	}()

	return func(waitCtx context.Context) error {
		cancel()
		select {
		case <-done:
			return nil
		case <-waitCtx.Done():
			return waitCtx.Err()
		}
	}
}
