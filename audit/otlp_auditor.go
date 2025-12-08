package audit

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// OTLPAuditorConfig holds configuration for the OTLP auditor.
type OTLPAuditorConfig struct {
	Logger   *slog.Logger
	Endpoint string // OTLP HTTP endpoint (e.g., "https://collector:4318" or "http://localhost:4318")
	Headers  string // Comma-separated key=value headers (e.g., "x-api-key=secret")
	Insecure bool   // Use HTTP instead of HTTPS
	CACert   string // Path to CA certificate file

	// Workspace metadata included in all log records.
	WorkspaceID    string
	WorkspaceName  string
	WorkspaceOwner string
}

// OTLPAuditor sends audit events to an OTLP-compatible endpoint.
type OTLPAuditor struct {
	logger         *slog.Logger
	loggerProvider *sdklog.LoggerProvider
	otelLogger     log.Logger

	workspaceID    string
	workspaceName  string
	workspaceOwner string

	mu     sync.Mutex
	closed bool
}

// loggingProcessor wraps a processor to log export errors.
type loggingProcessor struct {
	sdklog.Processor
	logger *slog.Logger
}

func (p *loggingProcessor) OnEmit(ctx context.Context, record *sdklog.Record) error {
	err := p.Processor.OnEmit(ctx, record)
	if err != nil {
		p.logger.Error("OTLP processor OnEmit failed", "error", err)
	}
	return err
}

func (p *loggingProcessor) Shutdown(ctx context.Context) error {
	err := p.Processor.Shutdown(ctx)
	if err != nil {
		p.logger.Error("OTLP processor Shutdown failed", "error", err)
	}
	return err
}

func (p *loggingProcessor) ForceFlush(ctx context.Context) error {
	err := p.Processor.ForceFlush(ctx)
	if err != nil {
		p.logger.Error("OTLP processor ForceFlush failed", "error", err)
	}
	return err
}

// NewOTLPAuditor creates a new OTLP auditor.
func NewOTLPAuditor(ctx context.Context, config OTLPAuditorConfig) (*OTLPAuditor, error) {
	if config.Endpoint == "" {
		return nil, fmt.Errorf("OTLP endpoint is required")
	}

	// Parse the endpoint URL to extract host:port.
	parsedURL, err := url.Parse(config.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OTLP endpoint URL: %w", err)
	}

	// Use WithEndpoint (host:port) which automatically appends /v1/logs.
	host := parsedURL.Host
	if host == "" {
		return nil, fmt.Errorf("OTLP endpoint must include host: %s", config.Endpoint)
	}

	opts := []otlploghttp.Option{
		otlploghttp.WithEndpoint(host),
	}

	// Parse and add headers.
	if config.Headers != "" {
		headers := parseHeaders(config.Headers)
		opts = append(opts, otlploghttp.WithHeaders(headers))
	}

	// Configure TLS/Insecure mode.
	// Use insecure if explicitly set OR if the URL scheme is http.
	useInsecure := config.Insecure || parsedURL.Scheme == "http"
	if useInsecure {
		opts = append(opts, otlploghttp.WithInsecure())
		config.Logger.Debug("OTLP auditor using insecure mode (no TLS)")
	} else if config.CACert != "" {
		// Custom CA certificate.
		tlsConfig, err := buildTLSConfig(config.CACert)
		if err != nil {
			return nil, fmt.Errorf("failed to configure TLS: %w", err)
		}
		opts = append(opts, otlploghttp.WithTLSClientConfig(tlsConfig))
		config.Logger.Debug("OTLP auditor using custom CA certificate", "path", config.CACert)
	}
	// Otherwise, use system CA pool (default behavior, no option needed).

	// Create the exporter.
	exporter, err := otlploghttp.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP exporter: %w", err)
	}

	// Create resource with service name.
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName("boundary"),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Create batch processor with shorter intervals for debugging.
	batchProcessor := sdklog.NewBatchProcessor(exporter,
		sdklog.WithExportInterval(5*time.Second),
		sdklog.WithExportMaxBatchSize(1), // Export immediately for debugging
	)

	// Wrap with logging processor to catch errors.
	loggingProc := &loggingProcessor{
		Processor: batchProcessor,
		logger:    config.Logger,
	}

	// Create the logger provider.
	provider := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(loggingProc),
		sdklog.WithResource(res),
	)

	config.Logger.Info("OTLP auditor initialized", "endpoint", host, "insecure", useInsecure)

	return &OTLPAuditor{
		logger:         config.Logger,
		loggerProvider: provider,
		otelLogger:     provider.Logger("boundary.audit"),
		workspaceID:    config.WorkspaceID,
		workspaceName:  config.WorkspaceName,
		workspaceOwner: config.WorkspaceOwner,
	}, nil
}

// AuditRequest sends the request to the OTLP endpoint.
func (a *OTLPAuditor) AuditRequest(req Request) {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	a.mu.Unlock()

	// Build log record.
	var record log.Record
	record.SetTimestamp(time.Now())
	record.SetBody(log.StringValue("network_access"))

	// Set severity based on decision.
	if req.Allowed {
		record.SetSeverity(log.SeverityInfo)
		record.SetSeverityText("INFO")
	} else {
		record.SetSeverity(log.SeverityWarn)
		record.SetSeverityText("WARN")
	}

	// Add attributes.
	attrs := []log.KeyValue{
		log.String("decision", boolToDecision(req.Allowed)),
		log.String("http.method", req.Method),
		log.String("http.url", req.URL),
		log.String("http.host", req.Host),
	}

	if req.Rule != "" {
		attrs = append(attrs, log.String("rule", req.Rule))
	}

	// Add workspace metadata if available.
	if a.workspaceID != "" {
		attrs = append(attrs, log.String("workspace.id", a.workspaceID))
	}
	if a.workspaceName != "" {
		attrs = append(attrs, log.String("workspace.name", a.workspaceName))
	}
	if a.workspaceOwner != "" {
		attrs = append(attrs, log.String("workspace.owner", a.workspaceOwner))
	}

	record.AddAttributes(attrs...)

	// Emit the log record.
	a.otelLogger.Emit(context.Background(), record)

	a.logger.Debug("OTLP audit event emitted",
		"method", req.Method,
		"url", req.URL,
		"decision", boolToDecision(req.Allowed))
}

// Close flushes pending logs and shuts down the provider.
func (a *OTLPAuditor) Close() error {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil
	}
	a.closed = true
	a.mu.Unlock()

	a.logger.Info("Shutting down OTLP auditor, flushing pending logs...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := a.loggerProvider.Shutdown(ctx); err != nil {
		a.logger.Error("failed to shutdown OTLP logger provider", "error", err)
		return err
	}
	return nil
}

// parseHeaders parses comma-separated key=value pairs into a map.
func parseHeaders(headers string) map[string]string {
	result := make(map[string]string)
	for _, pair := range strings.Split(headers, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 {
			result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return result
}

// buildTLSConfig creates a TLS configuration with a custom CA certificate.
func buildTLSConfig(caCertPath string) (*tls.Config, error) {
	// Load custom CA certificate.
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	return &tls.Config{
		RootCAs:    caCertPool,
		MinVersion: tls.VersionTLS12,
	}, nil
}

func boolToDecision(allowed bool) string {
	if allowed {
		return "allow"
	}
	return "deny"
}
