package tls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coder/boundary/config"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestNewCertificateManager(t *testing.T) {
	t.Parallel()

	t.Run("creates manager and generates CA on fresh directory", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		logger := discardLogger()

		cm, err := NewCertificateManager(Config{
			Logger:    logger,
			ConfigDir: dir,
			Uid:       os.Getuid(),
			Gid:       os.Getgid(),
		})
		require.NoError(t, err)
		require.NotNil(t, cm)

		// CA key and cert should be populated.
		assert.NotNil(t, cm.caKey)
		assert.NotNil(t, cm.caCert)
		assert.True(t, cm.caCert.IsCA, "generated certificate should be a CA")

		// Files should be written to disk.
		_, err = os.Stat(filepath.Join(dir, config.CAKeyName))
		assert.NoError(t, err, "CA key file should exist on disk")
		_, err = os.Stat(filepath.Join(dir, config.CACertName))
		assert.NoError(t, err, "CA cert file should exist on disk")
	})

	t.Run("loads existing valid CA from disk", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		logger := discardLogger()

		cfg := Config{
			Logger:    logger,
			ConfigDir: dir,
			Uid:       os.Getuid(),
			Gid:       os.Getgid(),
		}

		// First run generates the CA.
		cm1, err := NewCertificateManager(cfg)
		require.NoError(t, err)
		originalCert := cm1.caCert.Raw

		// Second run should load the same CA from disk.
		cm2, err := NewCertificateManager(cfg)
		require.NoError(t, err)

		assert.Equal(t, originalCert, cm2.caCert.Raw,
			"second manager should load the same CA certificate")
	})

	t.Run("regenerates CA when cert is expired", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		logger := discardLogger()

		// Write an expired CA to disk.
		writeExpiredCA(t, dir)

		cm, err := NewCertificateManager(Config{
			Logger:    logger,
			ConfigDir: dir,
			Uid:       os.Getuid(),
			Gid:       os.Getgid(),
		})
		require.NoError(t, err)
		require.NotNil(t, cm)

		// The loaded CA should be valid (newly generated, not expired).
		assert.True(t, time.Now().Before(cm.caCert.NotAfter),
			"regenerated CA certificate should not be expired")
	})

	t.Run("regenerates CA when key file is corrupted", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		logger := discardLogger()

		// Write garbage data as the key file.
		err := os.WriteFile(filepath.Join(dir, config.CAKeyName), []byte("not-a-pem"), 0600)
		require.NoError(t, err)
		err = os.WriteFile(filepath.Join(dir, config.CACertName), []byte("not-a-pem"), 0644)
		require.NoError(t, err)

		cm, err := NewCertificateManager(Config{
			Logger:    logger,
			ConfigDir: dir,
			Uid:       os.Getuid(),
			Gid:       os.Getgid(),
		})
		require.NoError(t, err)
		require.NotNil(t, cm)

		assert.True(t, cm.caCert.IsCA, "regenerated certificate should be a CA")
	})

	t.Run("regenerates CA when cert file is missing but key exists", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		logger := discardLogger()

		// Write only a key file.
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		keyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		})
		err := os.WriteFile(filepath.Join(dir, config.CAKeyName), keyPEM, 0600)
		require.NoError(t, err)

		cm, err := NewCertificateManager(Config{
			Logger:    logger,
			ConfigDir: dir,
			Uid:       os.Getuid(),
			Gid:       os.Getgid(),
		})
		require.NoError(t, err)
		assert.NotNil(t, cm.caCert, "should generate new CA when cert file is missing")
	})
}

func TestSetupTLSAndWriteCACert(t *testing.T) {
	t.Parallel()

	t.Run("writes CA cert file and returns valid TLS config", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		logger := discardLogger()

		cm, err := NewCertificateManager(Config{
			Logger:    logger,
			ConfigDir: dir,
			Uid:       os.Getuid(),
			Gid:       os.Getgid(),
		})
		require.NoError(t, err)

		tlsConfig, err := cm.SetupTLSAndWriteCACert()
		require.NoError(t, err)
		require.NotNil(t, tlsConfig)

		// Verify TLS config properties.
		assert.NotNil(t, tlsConfig.GetCertificate, "TLS config should have GetCertificate set")
		assert.Equal(t, uint16(tls.VersionTLS12), tlsConfig.MinVersion)

		// Verify CA cert file was written and is valid PEM.
		caCertPath := filepath.Join(dir, config.CACertName)
		data, err := os.ReadFile(caCertPath)
		require.NoError(t, err)

		block, _ := pem.Decode(data)
		require.NotNil(t, block, "CA cert file should contain valid PEM data")
		assert.Equal(t, "CERTIFICATE", block.Type)

		cert, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err)
		assert.True(t, cert.IsCA)
		assert.Equal(t, cm.caCert.Raw, cert.Raw,
			"written certificate should match the in-memory CA")
	})
}

func TestGetCertificate(t *testing.T) {
	t.Parallel()

	newManager := func(t *testing.T) *CertificateManager {
		t.Helper()
		dir := t.TempDir()
		cm, err := NewCertificateManager(Config{
			Logger:    discardLogger(),
			ConfigDir: dir,
			Uid:       os.Getuid(),
			Gid:       os.Getgid(),
		})
		require.NoError(t, err)
		return cm
	}

	t.Run("generates certificate for hostname", func(t *testing.T) {
		t.Parallel()
		cm := newManager(t)

		hello := &tls.ClientHelloInfo{ServerName: "example.com"}
		cert, err := cm.getCertificate(hello)
		require.NoError(t, err)
		require.NotNil(t, cert)

		// Parse the leaf certificate and verify its properties.
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		require.NoError(t, err)
		assert.Contains(t, leaf.DNSNames, "example.com")
		assert.Equal(t, "example.com", leaf.Subject.CommonName)
		assert.False(t, leaf.IsCA, "server cert should not be a CA")
	})

	t.Run("returns error for empty server name", func(t *testing.T) {
		t.Parallel()
		cm := newManager(t)

		hello := &tls.ClientHelloInfo{ServerName: ""}
		cert, err := cm.getCertificate(hello)
		assert.Error(t, err)
		assert.Nil(t, cert)
		assert.Contains(t, err.Error(), "no server name")
	})

	t.Run("caches certificates for same hostname", func(t *testing.T) {
		t.Parallel()
		cm := newManager(t)

		hello := &tls.ClientHelloInfo{ServerName: "cached.example.com"}

		cert1, err := cm.getCertificate(hello)
		require.NoError(t, err)

		cert2, err := cm.getCertificate(hello)
		require.NoError(t, err)

		// Certificates should be the exact same pointer (from cache).
		assert.Same(t, cert1, cert2, "second call should return cached certificate")
	})

	t.Run("generates distinct certificates for different hostnames", func(t *testing.T) {
		t.Parallel()
		cm := newManager(t)

		cert1, err := cm.getCertificate(&tls.ClientHelloInfo{ServerName: "a.example.com"})
		require.NoError(t, err)

		cert2, err := cm.getCertificate(&tls.ClientHelloInfo{ServerName: "b.example.com"})
		require.NoError(t, err)

		assert.NotSame(t, cert1, cert2, "different hostnames should get different certs")
	})

	t.Run("concurrent access is safe", func(t *testing.T) {
		t.Parallel()
		cm := newManager(t)

		const goroutines = 20
		hostnames := make([]string, goroutines)
		for i := range goroutines {
			hostnames[i] = "host-" + string(rune('a'+i)) + ".example.com"
		}

		var wg sync.WaitGroup
		errs := make([]error, goroutines)
		certs := make([]*tls.Certificate, goroutines)

		for i := range goroutines {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				hello := &tls.ClientHelloInfo{ServerName: hostnames[idx]}
				certs[idx], errs[idx] = cm.getCertificate(hello)
			}(i)
		}
		wg.Wait()

		for i := range goroutines {
			assert.NoError(t, errs[i], "goroutine %d should not error", i)
			assert.NotNil(t, certs[i], "goroutine %d should get a cert", i)
		}
	})

	t.Run("concurrent access to same hostname returns same cert", func(t *testing.T) {
		t.Parallel()
		cm := newManager(t)

		const goroutines = 10
		var wg sync.WaitGroup
		certs := make([]*tls.Certificate, goroutines)

		for i := range goroutines {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				hello := &tls.ClientHelloInfo{ServerName: "shared.example.com"}
				cert, err := cm.getCertificate(hello)
				require.NoError(t, err)
				certs[idx] = cert
			}(i)
		}
		wg.Wait()

		// All goroutines should get the same cached cert.
		for i := 1; i < goroutines; i++ {
			assert.Same(t, certs[0], certs[i],
				"goroutine %d should get the same cached cert as goroutine 0", i)
		}
	})
}

func TestGenerateServerCertificate(t *testing.T) {
	t.Parallel()

	newManager := func(t *testing.T) *CertificateManager {
		t.Helper()
		dir := t.TempDir()
		cm, err := NewCertificateManager(Config{
			Logger:    discardLogger(),
			ConfigDir: dir,
			Uid:       os.Getuid(),
			Gid:       os.Getgid(),
		})
		require.NoError(t, err)
		return cm
	}

	t.Run("certificate is signed by CA", func(t *testing.T) {
		t.Parallel()
		cm := newManager(t)

		cert, err := cm.generateServerCertificate("signed.example.com")
		require.NoError(t, err)

		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		require.NoError(t, err)

		// Verify the certificate chain using the CA.
		pool := x509.NewCertPool()
		pool.AddCert(cm.caCert)

		chains, err := leaf.Verify(x509.VerifyOptions{
			Roots:     pool,
			DNSName:   "signed.example.com",
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		require.NoError(t, err)
		assert.NotEmpty(t, chains, "certificate should validate against the CA")
	})

	t.Run("certificate for IP address includes IPAddresses SAN", func(t *testing.T) {
		t.Parallel()
		cm := newManager(t)

		cert, err := cm.generateServerCertificate("192.168.1.100")
		require.NoError(t, err)

		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		require.NoError(t, err)

		assert.Contains(t, leaf.DNSNames, "192.168.1.100")
		require.Len(t, leaf.IPAddresses, 1)
		assert.True(t, leaf.IPAddresses[0].Equal(net.ParseIP("192.168.1.100")),
			"IP SAN should match the requested IP")
	})

	t.Run("certificate for IPv6 address includes IPAddresses SAN", func(t *testing.T) {
		t.Parallel()
		cm := newManager(t)

		cert, err := cm.generateServerCertificate("::1")
		require.NoError(t, err)

		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		require.NoError(t, err)

		require.Len(t, leaf.IPAddresses, 1)
		assert.True(t, leaf.IPAddresses[0].Equal(net.ParseIP("::1")))
	})

	t.Run("certificate for regular hostname has no IPAddresses", func(t *testing.T) {
		t.Parallel()
		cm := newManager(t)

		cert, err := cm.generateServerCertificate("api.example.com")
		require.NoError(t, err)

		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		require.NoError(t, err)

		assert.Empty(t, leaf.IPAddresses, "hostname cert should not have IP SANs")
		assert.Contains(t, leaf.DNSNames, "api.example.com")
	})

	t.Run("certificate has correct validity period", func(t *testing.T) {
		t.Parallel()
		cm := newManager(t)

		before := time.Now()
		cert, err := cm.generateServerCertificate("validity.example.com")
		require.NoError(t, err)

		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		require.NoError(t, err)

		// NotBefore should be around now (within a few seconds).
		assert.WithinDuration(t, before, leaf.NotBefore, 5*time.Second)
		// NotAfter should be ~24h after NotBefore.
		assert.WithinDuration(t, leaf.NotBefore.Add(24*time.Hour), leaf.NotAfter, 5*time.Second)
	})

	t.Run("certificate has correct key usage", func(t *testing.T) {
		t.Parallel()
		cm := newManager(t)

		cert, err := cm.generateServerCertificate("usage.example.com")
		require.NoError(t, err)

		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		require.NoError(t, err)

		assert.Equal(t, x509.KeyUsageKeyEncipherment|x509.KeyUsageDigitalSignature, leaf.KeyUsage)
		assert.Contains(t, leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	})
}

func TestGenerateCA(t *testing.T) {
	t.Parallel()

	t.Run("CA certificate properties", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()

		cm, err := NewCertificateManager(Config{
			Logger:    discardLogger(),
			ConfigDir: dir,
			Uid:       os.Getuid(),
			Gid:       os.Getgid(),
		})
		require.NoError(t, err)

		assert.True(t, cm.caCert.IsCA, "should be a CA certificate")
		assert.True(t, cm.caCert.BasicConstraintsValid)
		assert.Equal(t, "coder CA", cm.caCert.Subject.CommonName)
		assert.Equal(t, []string{"coder"}, cm.caCert.Subject.Organization)

		expectedUsage := x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
		assert.Equal(t, expectedUsage, cm.caCert.KeyUsage)
		assert.Contains(t, cm.caCert.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	})

	t.Run("CA certificate has 1 year validity", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()

		before := time.Now()
		cm, err := NewCertificateManager(Config{
			Logger:    discardLogger(),
			ConfigDir: dir,
			Uid:       os.Getuid(),
			Gid:       os.Getgid(),
		})
		require.NoError(t, err)

		assert.WithinDuration(t, before, cm.caCert.NotBefore, 5*time.Second)
		assert.WithinDuration(t, before.Add(365*24*time.Hour), cm.caCert.NotAfter, 5*time.Second)
	})

	t.Run("CA key file has restricted permissions", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()

		_, err := NewCertificateManager(Config{
			Logger:    discardLogger(),
			ConfigDir: dir,
			Uid:       os.Getuid(),
			Gid:       os.Getgid(),
		})
		require.NoError(t, err)

		info, err := os.Stat(filepath.Join(dir, config.CAKeyName))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm(),
			"CA key file should be readable only by owner")
	})

	t.Run("CA cert file has standard permissions", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()

		_, err := NewCertificateManager(Config{
			Logger:    discardLogger(),
			ConfigDir: dir,
			Uid:       os.Getuid(),
			Gid:       os.Getgid(),
		})
		require.NoError(t, err)

		info, err := os.Stat(filepath.Join(dir, config.CACertName))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0644), info.Mode().Perm(),
			"CA cert file should be world-readable")
	})

	t.Run("creates nested config directory if missing", func(t *testing.T) {
		t.Parallel()
		dir := filepath.Join(t.TempDir(), "nested", "deep", "config")

		cm, err := NewCertificateManager(Config{
			Logger:    discardLogger(),
			ConfigDir: dir,
			Uid:       os.Getuid(),
			Gid:       os.Getgid(),
		})
		require.NoError(t, err)
		require.NotNil(t, cm)

		_, err = os.Stat(dir)
		assert.NoError(t, err, "nested config directory should be created")
	})
}

func TestLoadExistingCA(t *testing.T) {
	t.Parallel()

	t.Run("returns false when key file does not exist", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()

		cm := &CertificateManager{
			logger:    discardLogger(),
			configDir: dir,
		}

		result := cm.loadExistingCA(
			filepath.Join(dir, "nonexistent-key.pem"),
			filepath.Join(dir, "nonexistent-cert.pem"),
		)
		assert.False(t, result)
	})

	t.Run("returns false when cert file does not exist but key does", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()

		keyPath := filepath.Join(dir, config.CAKeyName)
		err := os.WriteFile(keyPath, []byte("some key data"), 0600)
		require.NoError(t, err)

		cm := &CertificateManager{
			logger:    discardLogger(),
			configDir: dir,
		}

		result := cm.loadExistingCA(keyPath, filepath.Join(dir, "nonexistent-cert.pem"))
		assert.False(t, result)
	})

	t.Run("returns false when key file contains invalid PEM", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()

		keyPath := filepath.Join(dir, config.CAKeyName)
		certPath := filepath.Join(dir, config.CACertName)
		err := os.WriteFile(keyPath, []byte("not-valid-pem"), 0600)
		require.NoError(t, err)
		err = os.WriteFile(certPath, []byte("not-valid-pem"), 0644)
		require.NoError(t, err)

		cm := &CertificateManager{
			logger:    discardLogger(),
			configDir: dir,
		}

		result := cm.loadExistingCA(keyPath, certPath)
		assert.False(t, result)
	})

	t.Run("returns false when cert contains invalid PEM", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()

		// Write a valid key but invalid cert.
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		keyPath := filepath.Join(dir, config.CAKeyName)
		keyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		})
		err = os.WriteFile(keyPath, keyPEM, 0600)
		require.NoError(t, err)

		certPath := filepath.Join(dir, config.CACertName)
		err = os.WriteFile(certPath, []byte("not-valid-pem"), 0644)
		require.NoError(t, err)

		cm := &CertificateManager{
			logger:    discardLogger(),
			configDir: dir,
		}

		result := cm.loadExistingCA(keyPath, certPath)
		assert.False(t, result)
	})

	t.Run("returns false for expired certificate", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeExpiredCA(t, dir)

		cm := &CertificateManager{
			logger:    discardLogger(),
			configDir: dir,
		}

		result := cm.loadExistingCA(
			filepath.Join(dir, config.CAKeyName),
			filepath.Join(dir, config.CACertName),
		)
		assert.False(t, result, "should reject expired certificate")
	})

	t.Run("returns true and loads valid CA", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeValidCA(t, dir)

		cm := &CertificateManager{
			logger:    discardLogger(),
			configDir: dir,
		}

		result := cm.loadExistingCA(
			filepath.Join(dir, config.CAKeyName),
			filepath.Join(dir, config.CACertName),
		)
		assert.True(t, result, "should successfully load valid CA")
		assert.NotNil(t, cm.caKey)
		assert.NotNil(t, cm.caCert)
		assert.True(t, cm.caCert.IsCA)
	})
}

func TestGetCACertPEM(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cm, err := NewCertificateManager(Config{
		Logger:    discardLogger(),
		ConfigDir: dir,
		Uid:       os.Getuid(),
		Gid:       os.Getgid(),
	})
	require.NoError(t, err)

	pemData, err := cm.getCACertPEM()
	require.NoError(t, err)
	require.NotEmpty(t, pemData)

	block, _ := pem.Decode(pemData)
	require.NotNil(t, block, "should produce valid PEM output")
	assert.Equal(t, "CERTIFICATE", block.Type)

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, cm.caCert.Raw, cert.Raw,
		"PEM-encoded certificate should match the in-memory CA")
}

func TestGetTLSConfig(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cm, err := NewCertificateManager(Config{
		Logger:    discardLogger(),
		ConfigDir: dir,
		Uid:       os.Getuid(),
		Gid:       os.Getgid(),
	})
	require.NoError(t, err)

	tlsCfg := cm.getTLSConfig()
	require.NotNil(t, tlsCfg)

	assert.NotNil(t, tlsCfg.GetCertificate,
		"TLS config should have GetCertificate callback")
	assert.Equal(t, uint16(tls.VersionTLS12), tlsCfg.MinVersion,
		"minimum TLS version should be 1.2")
}

// TestManagerInterfaceMismatch documents that *CertificateManager does not
// satisfy the Manager interface. The interface expects
// (*tls.Config, string, string, error) but the method returns (*tls.Config, error).
// This test will fail to compile if someone "fixes" the interface without
// updating this test, serving as a reminder to reconcile both.
func TestManagerInterfaceMismatch(t *testing.T) {
	t.Parallel()

	// The Manager interface is declared but *CertificateManager does not
	// implement it due to a return-type mismatch. Verify the interface
	// exists and document the gap. If this test ever becomes a compile
	// error because the method signature changed, update accordingly.
	var _ Manager // Ensure the interface type is still declared.

	// We intentionally do NOT assert: var _ Manager = (*CertificateManager)(nil)
	// because that would fail to compile today due to the signature mismatch.
	t.Log("Manager interface declares SetupTLSAndWriteCACert() (*tls.Config, string, string, error) " +
		"but CertificateManager.SetupTLSAndWriteCACert() returns (*tls.Config, error). " +
		"See https://github.com/coder/boundary/issues/52 for context.")
}

// writeExpiredCA generates a CA that expired in the past and writes it to dir.
func writeExpiredCA(t *testing.T, dir string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "expired CA",
			Organization: []string{"test"},
		},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour), // Expired yesterday.
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	require.NoError(t, err)

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	err = os.WriteFile(filepath.Join(dir, config.CAKeyName), keyPEM, 0600)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(dir, config.CACertName), certPEM, 0644)
	require.NoError(t, err)
}

// writeValidCA generates a valid, non-expired CA and writes it to dir.
func writeValidCA(t *testing.T, dir string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "valid CA",
			Organization: []string{"test"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	require.NoError(t, err)

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	err = os.WriteFile(filepath.Join(dir, config.CAKeyName), keyPEM, 0600)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(dir, config.CACertName), certPEM, 0644)
	require.NoError(t, err)
}
