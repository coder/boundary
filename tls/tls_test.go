package tls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewCertificateManager(t *testing.T) {
	// Create temporary directory for testing
	tmpDir := t.TempDir()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	config := Config{
		Logger:    logger,
		ConfigDir: tmpDir,
		Uid:       os.Getuid(),
		Gid:       os.Getgid(),
	}

	cm, err := NewCertificateManager(config)
	if err != nil {
		t.Fatalf("Failed to create certificate manager: %v", err)
	}

	if cm == nil {
		t.Fatal("Certificate manager is nil")
	}

	// Verify CA cert and key were created
	if cm.caCert == nil {
		t.Error("CA certificate is nil")
	}

	if cm.caKey == nil {
		t.Error("CA key is nil")
	}

	// Verify CA cert files exist
	caKeyPath := filepath.Join(tmpDir, "ca-key.pem")
	caCertPath := filepath.Join(tmpDir, "ca-cert.pem")

	if _, err := os.Stat(caKeyPath); os.IsNotExist(err) {
		t.Error("CA key file was not created")
	}

	if _, err := os.Stat(caCertPath); os.IsNotExist(err) {
		t.Error("CA cert file was not created")
	}
}

func TestSetupTLSAndWriteCACert(t *testing.T) {
	tmpDir := t.TempDir()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	config := Config{
		Logger:    logger,
		ConfigDir: tmpDir,
		Uid:       os.Getuid(),
		Gid:       os.Getgid(),
	}

	cm, err := NewCertificateManager(config)
	if err != nil {
		t.Fatalf("Failed to create certificate manager: %v", err)
	}

	tlsConfig, caCertPath, configDir, err := cm.SetupTLSAndWriteCACert()
	if err != nil {
		t.Fatalf("Failed to setup TLS: %v", err)
	}

	// Verify TLS config
	if tlsConfig == nil {
		t.Fatal("TLS config is nil")
	}

	if tlsConfig.GetCertificate == nil {
		t.Error("TLS config GetCertificate is nil")
	}

	if tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("Expected MinVersion TLS 1.2, got %d", tlsConfig.MinVersion)
	}

	// Verify CA cert path
	if caCertPath == "" {
		t.Error("CA cert path is empty")
	}

	expectedCertPath := filepath.Join(tmpDir, "ca-cert.pem")
	if caCertPath != expectedCertPath {
		t.Errorf("Expected CA cert path %s, got %s", expectedCertPath, caCertPath)
	}

	// Verify config dir
	if configDir != tmpDir {
		t.Errorf("Expected config dir %s, got %s", tmpDir, configDir)
	}

	// Verify CA cert file exists and is valid PEM
	certData, err := os.ReadFile(caCertPath)
	if err != nil {
		t.Fatalf("Failed to read CA cert file: %v", err)
	}

	block, _ := pem.Decode(certData)
	if block == nil {
		t.Fatal("Failed to decode CA cert PEM")
	}

	if block.Type != "CERTIFICATE" {
		t.Errorf("Expected PEM type CERTIFICATE, got %s", block.Type)
	}

	// Verify certificate is valid
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse CA certificate: %v", err)
	}

	if !cert.IsCA {
		t.Error("Certificate is not marked as CA")
	}
}

func TestLoadExistingCA(t *testing.T) {
	tmpDir := t.TempDir()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	config := Config{
		Logger:    logger,
		ConfigDir: tmpDir,
		Uid:       os.Getuid(),
		Gid:       os.Getgid(),
	}

	// Create first certificate manager
	cm1, err := NewCertificateManager(config)
	if err != nil {
		t.Fatalf("Failed to create first certificate manager: %v", err)
	}

	originalSerial := cm1.caCert.SerialNumber

	// Create second certificate manager - should load existing CA
	cm2, err := NewCertificateManager(config)
	if err != nil {
		t.Fatalf("Failed to create second certificate manager: %v", err)
	}

	// Verify the same CA was loaded
	if cm2.caCert.SerialNumber.Cmp(originalSerial) != 0 {
		t.Error("Second manager did not load the same CA certificate")
	}
}

func TestGetCertificate(t *testing.T) {
	tmpDir := t.TempDir()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	config := Config{
		Logger:    logger,
		ConfigDir: tmpDir,
		Uid:       os.Getuid(),
		Gid:       os.Getgid(),
	}

	cm, err := NewCertificateManager(config)
	if err != nil {
		t.Fatalf("Failed to create certificate manager: %v", err)
	}

	testCases := []struct {
		name       string
		serverName string
		shouldFail bool
	}{
		{
			name:       "valid hostname",
			serverName: "example.com",
			shouldFail: false,
		},
		{
			name:       "valid IP address",
			serverName: "192.168.1.1",
			shouldFail: false,
		},
		{
			name:       "empty server name",
			serverName: "",
			shouldFail: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hello := &tls.ClientHelloInfo{
				ServerName: tc.serverName,
			}

			cert, err := cm.getCertificate(hello)

			if tc.shouldFail {
				if err == nil {
					t.Error("Expected error for empty server name")
				}
				return
			}

			if err != nil {
				t.Fatalf("Failed to get certificate: %v", err)
			}

			if cert == nil {
				t.Fatal("Certificate is nil")
			}

			if len(cert.Certificate) == 0 {
				t.Fatal("Certificate chain is empty")
			}

			// Parse the certificate
			x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				t.Fatalf("Failed to parse certificate: %v", err)
			}

			// Verify certificate properties
			if x509Cert.Subject.CommonName != tc.serverName {
				t.Errorf("Expected CN %s, got %s", tc.serverName, x509Cert.Subject.CommonName)
			}

			// Verify certificate validity period
			now := time.Now()
			if now.Before(x509Cert.NotBefore) {
				t.Error("Certificate is not yet valid")
			}

			if now.After(x509Cert.NotAfter) {
				t.Error("Certificate has expired")
			}

			// Verify certificate is signed by our CA
			roots := x509.NewCertPool()
			roots.AddCert(cm.caCert)

			opts := x509.VerifyOptions{
				Roots:     roots,
				DNSName:   tc.serverName,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}

			// Skip DNS verification for IP addresses
			if tc.serverName == "192.168.1.1" {
				opts.DNSName = ""
			}

			if _, err := x509Cert.Verify(opts); err != nil {
				t.Errorf("Certificate verification failed: %v", err)
			}
		})
	}
}

func TestCertificateCache(t *testing.T) {
	tmpDir := t.TempDir()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	config := Config{
		Logger:    logger,
		ConfigDir: tmpDir,
		Uid:       os.Getuid(),
		Gid:       os.Getgid(),
	}

	cm, err := NewCertificateManager(config)
	if err != nil {
		t.Fatalf("Failed to create certificate manager: %v", err)
	}

	hostname := "cached.example.com"
	hello := &tls.ClientHelloInfo{
		ServerName: hostname,
	}

	// First request - should generate certificate
	cert1, err := cm.getCertificate(hello)
	if err != nil {
		t.Fatalf("Failed to get first certificate: %v", err)
	}

	// Second request - should return cached certificate
	cert2, err := cm.getCertificate(hello)
	if err != nil {
		t.Fatalf("Failed to get second certificate: %v", err)
	}

	// Verify both certificates are the same instance
	if cert1 != cert2 {
		t.Error("Second certificate request did not return cached certificate")
	}

	// Verify cache contains the certificate
	cm.mutex.RLock()
	cachedCert, exists := cm.certCache[hostname]
	cm.mutex.RUnlock()

	if !exists {
		t.Error("Certificate not found in cache")
	}

	if cachedCert != cert1 {
		t.Error("Cached certificate does not match returned certificate")
	}
}

func TestGenerateServerCertificateWithIP(t *testing.T) {
	tmpDir := t.TempDir()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	config := Config{
		Logger:    logger,
		ConfigDir: tmpDir,
		Uid:       os.Getuid(),
		Gid:       os.Getgid(),
	}

	cm, err := NewCertificateManager(config)
	if err != nil {
		t.Fatalf("Failed to create certificate manager: %v", err)
	}

	ipAddress := "10.0.0.1"
	cert, err := cm.generateServerCertificate(ipAddress)
	if err != nil {
		t.Fatalf("Failed to generate certificate for IP: %v", err)
	}

	// Parse certificate
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Verify IP addresses are set
	if len(x509Cert.IPAddresses) == 0 {
		t.Error("Certificate does not contain IP addresses")
	}

	expectedIP := "10.0.0.1"
	found := false
	for _, ip := range x509Cert.IPAddresses {
		if ip.String() == expectedIP {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Certificate does not contain expected IP %s", expectedIP)
	}
}

func TestGetCACertPEM(t *testing.T) {
	tmpDir := t.TempDir()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	config := Config{
		Logger:    logger,
		ConfigDir: tmpDir,
		Uid:       os.Getuid(),
		Gid:       os.Getgid(),
	}

	cm, err := NewCertificateManager(config)
	if err != nil {
		t.Fatalf("Failed to create certificate manager: %v", err)
	}

	pemData, err := cm.getCACertPEM()
	if err != nil {
		t.Fatalf("Failed to get CA cert PEM: %v", err)
	}

	if len(pemData) == 0 {
		t.Fatal("CA cert PEM is empty")
	}

	// Verify PEM can be decoded
	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Fatal("Failed to decode CA cert PEM")
	}

	if block.Type != "CERTIFICATE" {
		t.Errorf("Expected PEM type CERTIFICATE, got %s", block.Type)
	}

	// Verify certificate matches
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate from PEM: %v", err)
	}

	if cert.SerialNumber.Cmp(cm.caCert.SerialNumber) != 0 {
		t.Error("PEM certificate does not match CA certificate")
	}
}

func TestConcurrentCertificateGeneration(t *testing.T) {
	tmpDir := t.TempDir()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	config := Config{
		Logger:    logger,
		ConfigDir: tmpDir,
		Uid:       os.Getuid(),
		Gid:       os.Getgid(),
	}

	cm, err := NewCertificateManager(config)
	if err != nil {
		t.Fatalf("Failed to create certificate manager: %v", err)
	}

	hostname := "concurrent.example.com"
	numGoroutines := 10
	results := make(chan *tls.Certificate, numGoroutines)
	errors := make(chan error, numGoroutines)

	// Launch multiple goroutines requesting the same certificate
	for i := 0; i < numGoroutines; i++ {
		go func() {
			hello := &tls.ClientHelloInfo{
				ServerName: hostname,
			}
			cert, err := cm.getCertificate(hello)
			if err != nil {
				errors <- err
				return
			}
			results <- cert
		}()
	}

	// Collect results
	var certs []*tls.Certificate
	for i := 0; i < numGoroutines; i++ {
		select {
		case cert := <-results:
			certs = append(certs, cert)
		case err := <-errors:
			t.Fatalf("Error in goroutine: %v", err)
		}
	}

	// Verify all goroutines got the same certificate instance
	firstCert := certs[0]
	for i, cert := range certs {
		if cert != firstCert {
			t.Errorf("Goroutine %d received different certificate instance", i)
		}
	}

	// Verify cache contains only one entry
	cm.mutex.RLock()
	cacheSize := len(cm.certCache)
	cm.mutex.RUnlock()

	if cacheSize != 1 {
		t.Errorf("Expected cache size 1, got %d", cacheSize)
	}
}
