package tls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/coder/boundary/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestConfig returns a Config pointing at a fresh t.TempDir() owned
// by the current user, suitable for tests that need to write CA files.
func newTestConfig(t *testing.T) Config {
	t.Helper()
	u, err := user.Current()
	require.NoError(t, err)

	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)

	return Config{
		Logger:    slog.Default(),
		ConfigDir: t.TempDir(),
		Uid:       uid,
		Gid:       gid,
	}
}

// newTestManager creates a CertificateManager backed by a temporary directory.
// It fails the test immediately if the manager cannot be created.
func newTestManager(t *testing.T) (*CertificateManager, Config) {
	t.Helper()
	cfg := newTestConfig(t)
	cm, err := NewCertificateManager(cfg)
	require.NoError(t, err)
	return cm, cfg
}

// ----- NewCertificateManager tests -----

func TestNewCertificateManager_GeneratesCAFiles(t *testing.T) {
	t.Parallel()

	cfg := newTestConfig(t)
	cm, err := NewCertificateManager(cfg)
	require.NoError(t, err)
	require.NotNil(t, cm)

	// CA key and cert files must exist after first initialization.
	keyPath := filepath.Join(cfg.ConfigDir, config.CAKeyName)
	certPath := filepath.Join(cfg.ConfigDir, config.CACertName)
	assert.FileExists(t, keyPath)
	assert.FileExists(t, certPath)

	// The generated CA certificate must be a valid CA.
	require.NotNil(t, cm.caCert)
	assert.True(t, cm.caCert.IsCA, "generated certificate must be a CA")
	assert.True(t, cm.caCert.BasicConstraintsValid)
	assert.Equal(t, "coder CA", cm.caCert.Subject.CommonName)
}

func TestNewCertificateManager_LoadsExistingCA(t *testing.T) {
	t.Parallel()

	cfg := newTestConfig(t)

	// First call generates the CA.
	cm1, err := NewCertificateManager(cfg)
	require.NoError(t, err)
	originalSerial := cm1.caCert.SerialNumber

	// Second call with the same config directory must load the existing CA,
	// not generate a new one. The serial number should stay the same.
	cm2, err := NewCertificateManager(cfg)
	require.NoError(t, err)
	require.Equal(t, 0, originalSerial.Cmp(cm2.caCert.SerialNumber),
		"serial numbers must match when loading existing CA")
}

func TestNewCertificateManager_CreatesConfigDir(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	nested := filepath.Join(base, "deep", "nested", "dir")
	u, err := user.Current()
	require.NoError(t, err)
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)

	cfg := Config{
		Logger:    slog.Default(),
		ConfigDir: nested,
		Uid:       uid,
		Gid:       gid,
	}

	cm, err := NewCertificateManager(cfg)
	require.NoError(t, err)
	require.NotNil(t, cm)

	info, err := os.Stat(nested)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

func TestNewCertificateManager_UnwritableDir(t *testing.T) {
	t.Parallel()

	// Use a path under /proc which is guaranteed to be non-writable as
	// a regular user.
	cfg := Config{
		Logger:    slog.Default(),
		ConfigDir: "/proc/1/nonexistent",
		Uid:       os.Getuid(),
		Gid:       os.Getgid(),
	}

	_, err := NewCertificateManager(cfg)
	require.Error(t, err, "should fail when config directory is not writable")
}

// ----- loadExistingCA tests -----

func TestLoadExistingCA_MissingKeyFile(t *testing.T) {
	t.Parallel()

	cm, cfg := newTestManager(t)
	keyPath := filepath.Join(cfg.ConfigDir, config.CAKeyName)
	certPath := filepath.Join(cfg.ConfigDir, config.CACertName)

	// Remove key file.
	require.NoError(t, os.Remove(keyPath))

	cm2 := &CertificateManager{logger: slog.Default()}
	assert.False(t, cm2.loadExistingCA(keyPath, certPath),
		"should return false when key file is missing")
	_ = cm // keep cm alive to silence lint
}

func TestLoadExistingCA_MissingCertFile(t *testing.T) {
	t.Parallel()

	cm, cfg := newTestManager(t)
	keyPath := filepath.Join(cfg.ConfigDir, config.CAKeyName)
	certPath := filepath.Join(cfg.ConfigDir, config.CACertName)

	// Remove cert file.
	require.NoError(t, os.Remove(certPath))

	cm2 := &CertificateManager{logger: slog.Default()}
	assert.False(t, cm2.loadExistingCA(keyPath, certPath),
		"should return false when cert file is missing")
	_ = cm
}

func TestLoadExistingCA_InvalidKeyPEM(t *testing.T) {
	t.Parallel()

	_, cfg := newTestManager(t)
	keyPath := filepath.Join(cfg.ConfigDir, config.CAKeyName)
	certPath := filepath.Join(cfg.ConfigDir, config.CACertName)

	// Overwrite key with garbage.
	require.NoError(t, os.WriteFile(keyPath, []byte("not-a-pem"), 0600))

	cm := &CertificateManager{logger: slog.Default()}
	assert.False(t, cm.loadExistingCA(keyPath, certPath),
		"should return false when key PEM is invalid")
}

func TestLoadExistingCA_InvalidCertPEM(t *testing.T) {
	t.Parallel()

	_, cfg := newTestManager(t)
	keyPath := filepath.Join(cfg.ConfigDir, config.CAKeyName)
	certPath := filepath.Join(cfg.ConfigDir, config.CACertName)

	// Overwrite cert with garbage.
	require.NoError(t, os.WriteFile(certPath, []byte("not-a-pem"), 0644))

	cm := &CertificateManager{logger: slog.Default()}
	assert.False(t, cm.loadExistingCA(keyPath, certPath),
		"should return false when cert PEM is invalid")
}

func TestLoadExistingCA_ExpiredCert(t *testing.T) {
	t.Parallel()

	cm, cfg := newTestManager(t)
	certPath := filepath.Join(cfg.ConfigDir, config.CACertName)

	// Write an expired certificate using the same CA key so the PEM is valid.
	expiredTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(999),
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-1 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	expiredDER, err := x509.CreateCertificate(
		nil, // not needed for self-signed with template
		&expiredTemplate, &expiredTemplate,
		&cm.caKey.PublicKey, cm.caKey,
	)
	// x509.CreateCertificate with nil rand uses crypto/rand internally,
	// so we need the proper call.
	_ = expiredDER
	_ = err

	// Simpler approach: just overwrite with the helper.
	expiredDER2, err := x509.CreateCertificate(
		readerForTest(), &expiredTemplate, &expiredTemplate,
		&cm.caKey.PublicKey, cm.caKey,
	)
	require.NoError(t, err)

	expiredPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: expiredDER2,
	})
	require.NoError(t, os.WriteFile(certPath, expiredPEM, 0644))

	keyPath := filepath.Join(cfg.ConfigDir, config.CAKeyName)
	cm2 := &CertificateManager{logger: slog.Default()}
	assert.False(t, cm2.loadExistingCA(keyPath, certPath),
		"should return false when certificate is expired")
}

func TestLoadExistingCA_ValidFiles(t *testing.T) {
	t.Parallel()

	_, cfg := newTestManager(t)
	keyPath := filepath.Join(cfg.ConfigDir, config.CAKeyName)
	certPath := filepath.Join(cfg.ConfigDir, config.CACertName)

	cm := &CertificateManager{logger: slog.Default()}
	assert.True(t, cm.loadExistingCA(keyPath, certPath),
		"should return true for valid CA files")
	assert.NotNil(t, cm.caKey, "caKey must be populated after successful load")
	assert.NotNil(t, cm.caCert, "caCert must be populated after successful load")
	assert.True(t, cm.caCert.IsCA)
}

// ----- generateCA tests -----

func TestGenerateCA_WritesFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cm := &CertificateManager{
		logger:    slog.Default(),
		configDir: dir,
		uid:       os.Getuid(),
		gid:       os.Getgid(),
	}

	keyPath := filepath.Join(dir, config.CAKeyName)
	certPath := filepath.Join(dir, config.CACertName)

	err := cm.generateCA(keyPath, certPath)
	require.NoError(t, err)

	// Verify files exist and have correct permissions.
	keyInfo, err := os.Stat(keyPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), keyInfo.Mode().Perm(),
		"CA key file must have mode 0600")

	certInfo, err := os.Stat(certPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0644), certInfo.Mode().Perm(),
		"CA cert file must have mode 0644")
}

func TestGenerateCA_ProducesValidCACert(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cm := &CertificateManager{
		logger:    slog.Default(),
		configDir: dir,
		uid:       os.Getuid(),
		gid:       os.Getgid(),
	}

	keyPath := filepath.Join(dir, config.CAKeyName)
	certPath := filepath.Join(dir, config.CACertName)
	require.NoError(t, cm.generateCA(keyPath, certPath))

	require.NotNil(t, cm.caCert)
	assert.True(t, cm.caCert.IsCA)
	assert.True(t, cm.caCert.BasicConstraintsValid)
	assert.Contains(t, cm.caCert.Subject.Organization, "coder")
	assert.Equal(t, "coder CA", cm.caCert.Subject.CommonName)

	// Validity window.
	assert.True(t, cm.caCert.NotBefore.Before(time.Now()))
	assert.True(t, cm.caCert.NotAfter.After(time.Now()))

	// Key usage must include cert signing.
	assert.NotZero(t, cm.caCert.KeyUsage&x509.KeyUsageCertSign)

	// CA key must be set.
	require.NotNil(t, cm.caKey)
}

func TestGenerateCA_PEMFilesAreParseable(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cm := &CertificateManager{
		logger:    slog.Default(),
		configDir: dir,
		uid:       os.Getuid(),
		gid:       os.Getgid(),
	}

	keyPath := filepath.Join(dir, config.CAKeyName)
	certPath := filepath.Join(dir, config.CACertName)
	require.NoError(t, cm.generateCA(keyPath, certPath))

	// Key PEM is parseable.
	keyData, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	keyBlock, _ := pem.Decode(keyData)
	require.NotNil(t, keyBlock, "key PEM must be decodable")
	assert.Equal(t, "RSA PRIVATE KEY", keyBlock.Type)
	_, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	require.NoError(t, err, "key must be parseable as PKCS1")

	// Cert PEM is parseable.
	certData, err := os.ReadFile(certPath)
	require.NoError(t, err)
	certBlock, _ := pem.Decode(certData)
	require.NotNil(t, certBlock, "cert PEM must be decodable")
	assert.Equal(t, "CERTIFICATE", certBlock.Type)
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	require.NoError(t, err, "cert must be parseable as X.509")
	assert.True(t, cert.IsCA)
}

// ----- SetupTLSAndWriteCACert tests -----

func TestSetupTLSAndWriteCACert_ReturnsTLSConfig(t *testing.T) {
	t.Parallel()

	cm, _ := newTestManager(t)
	tlsConfig, err := cm.SetupTLSAndWriteCACert()
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)

	assert.Equal(t, uint16(tls.VersionTLS12), tlsConfig.MinVersion,
		"TLS config must use minimum TLS 1.2")
	assert.NotNil(t, tlsConfig.GetCertificate,
		"TLS config must have GetCertificate callback")
}

func TestSetupTLSAndWriteCACert_WritesCACertFile(t *testing.T) {
	t.Parallel()

	cm, cfg := newTestManager(t)
	_, err := cm.SetupTLSAndWriteCACert()
	require.NoError(t, err)

	caCertPath := filepath.Join(cfg.ConfigDir, config.CACertName)
	data, err := os.ReadFile(caCertPath)
	require.NoError(t, err)
	assert.NotEmpty(t, data, "CA cert file must not be empty")

	// File should contain valid PEM.
	block, _ := pem.Decode(data)
	require.NotNil(t, block)
	assert.Equal(t, "CERTIFICATE", block.Type)
}

// ----- getTLSConfig tests -----

func TestGetTLSConfig_MinVersion(t *testing.T) {
	t.Parallel()

	cm, _ := newTestManager(t)
	tlsCfg := cm.getTLSConfig()
	assert.Equal(t, uint16(tls.VersionTLS12), tlsCfg.MinVersion)
}

func TestGetTLSConfig_HasGetCertificate(t *testing.T) {
	t.Parallel()

	cm, _ := newTestManager(t)
	tlsCfg := cm.getTLSConfig()
	assert.NotNil(t, tlsCfg.GetCertificate)
}

// ----- getCACertPEM tests -----

func TestGetCACertPEM_ReturnsPEM(t *testing.T) {
	t.Parallel()

	cm, _ := newTestManager(t)
	pemData, err := cm.getCACertPEM()
	require.NoError(t, err)
	require.NotEmpty(t, pemData)

	block, _ := pem.Decode(pemData)
	require.NotNil(t, block, "returned data must be valid PEM")
	assert.Equal(t, "CERTIFICATE", block.Type)

	// The decoded cert should match the CA cert.
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.True(t, cert.IsCA)
}

// ----- getCertificate tests -----

func TestGetCertificate_EmptyServerName(t *testing.T) {
	t.Parallel()

	cm, _ := newTestManager(t)
	_, err := cm.getCertificate(&tls.ClientHelloInfo{
		ServerName: "",
	})
	require.Error(t, err, "empty ServerName must produce an error")
	assert.Contains(t, err.Error(), "no server name")
}

func TestGetCertificate_GeneratesCertForHostname(t *testing.T) {
	t.Parallel()

	cm, _ := newTestManager(t)
	cert, err := cm.getCertificate(&tls.ClientHelloInfo{
		ServerName: "example.com",
	})
	require.NoError(t, err)
	require.NotNil(t, cert)
	require.NotEmpty(t, cert.Certificate)

	// Parse the leaf cert and verify it was signed by our CA.
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	assert.Equal(t, "example.com", leaf.Subject.CommonName)
	assert.Contains(t, leaf.DNSNames, "example.com")

	// Verify the cert chains to our CA.
	pool := x509.NewCertPool()
	pool.AddCert(cm.caCert)
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots: pool,
	})
	require.NoError(t, err, "generated cert must chain to the CA")
}

func TestGetCertificate_CachesSameHostname(t *testing.T) {
	t.Parallel()

	cm, _ := newTestManager(t)
	hello := &tls.ClientHelloInfo{ServerName: "cached.example.com"}

	cert1, err := cm.getCertificate(hello)
	require.NoError(t, err)

	cert2, err := cm.getCertificate(hello)
	require.NoError(t, err)

	// Same pointer means it came from the cache.
	assert.Same(t, cert1, cert2, "repeated calls must return the cached cert")
}

func TestGetCertificate_DifferentHostsGetDifferentCerts(t *testing.T) {
	t.Parallel()

	cm, _ := newTestManager(t)

	cert1, err := cm.getCertificate(&tls.ClientHelloInfo{ServerName: "alpha.example.com"})
	require.NoError(t, err)

	cert2, err := cm.getCertificate(&tls.ClientHelloInfo{ServerName: "beta.example.com"})
	require.NoError(t, err)

	assert.NotSame(t, cert1, cert2,
		"different hostnames must produce different certificates")
}

func TestGetCertificate_ConcurrentRequests(t *testing.T) {
	t.Parallel()

	cm, _ := newTestManager(t)
	const hostname = "concurrent.example.com"
	const goroutines = 20

	results := make([]*tls.Certificate, goroutines)
	errs := make([]error, goroutines)

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			cert, err := cm.getCertificate(&tls.ClientHelloInfo{
				ServerName: hostname,
			})
			results[idx] = cert
			errs[idx] = err
		}(i)
	}

	wg.Wait()

	// All goroutines must succeed and return the same pointer.
	for i := range goroutines {
		require.NoError(t, errs[i], "goroutine %d must not error", i)
		require.NotNil(t, results[i], "goroutine %d must produce a cert", i)
		assert.Same(t, results[0], results[i],
			"goroutine %d must return the same cached cert", i)
	}
}

// ----- generateServerCertificate tests -----

func TestGenerateServerCertificate_DNSHostname(t *testing.T) {
	t.Parallel()

	cm, _ := newTestManager(t)
	cert, err := cm.generateServerCertificate("api.example.com")
	require.NoError(t, err)
	require.NotNil(t, cert)

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)

	assert.Equal(t, "api.example.com", leaf.Subject.CommonName)
	assert.Contains(t, leaf.DNSNames, "api.example.com")
	assert.Empty(t, leaf.IPAddresses, "DNS hostname must not produce IP SANs")
	assert.Contains(t, leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
}

func TestGenerateServerCertificate_IPAddress(t *testing.T) {
	t.Parallel()

	cm, _ := newTestManager(t)
	cert, err := cm.generateServerCertificate("192.168.1.100")
	require.NoError(t, err)
	require.NotNil(t, cert)

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)

	assert.Equal(t, "192.168.1.100", leaf.Subject.CommonName)
	assert.Contains(t, leaf.DNSNames, "192.168.1.100",
		"IP hostname also appears in DNSNames")
	require.Len(t, leaf.IPAddresses, 1)
	assert.Equal(t, "192.168.1.100", leaf.IPAddresses[0].String())
}

func TestGenerateServerCertificate_IPv6Address(t *testing.T) {
	t.Parallel()

	cm, _ := newTestManager(t)
	cert, err := cm.generateServerCertificate("::1")
	require.NoError(t, err)
	require.NotNil(t, cert)

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)

	require.Len(t, leaf.IPAddresses, 1)
	assert.Equal(t, "::1", leaf.IPAddresses[0].String())
}

func TestGenerateServerCertificate_Validity(t *testing.T) {
	t.Parallel()

	cm, _ := newTestManager(t)
	cert, err := cm.generateServerCertificate("validity.example.com")
	require.NoError(t, err)

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)

	assert.True(t, leaf.NotBefore.Before(time.Now().Add(time.Minute)),
		"NotBefore must be around now")
	assert.True(t, leaf.NotAfter.After(time.Now()),
		"NotAfter must be in the future")
	// Server certs use a 24-hour validity window.
	assert.True(t, leaf.NotAfter.Before(time.Now().Add(25*time.Hour)),
		"NotAfter must be within ~24 hours")
}

func TestGenerateServerCertificate_SignedByCA(t *testing.T) {
	t.Parallel()

	cm, _ := newTestManager(t)
	cert, err := cm.generateServerCertificate("signed.example.com")
	require.NoError(t, err)

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)

	// The leaf must chain to our CA.
	pool := x509.NewCertPool()
	pool.AddCert(cm.caCert)
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots: pool,
	})
	require.NoError(t, err)
	require.NotEmpty(t, chains)
}

func TestGenerateServerCertificate_IsNotCA(t *testing.T) {
	t.Parallel()

	cm, _ := newTestManager(t)
	cert, err := cm.generateServerCertificate("leaf.example.com")
	require.NoError(t, err)

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)

	assert.False(t, leaf.IsCA, "server cert must not be a CA")
}

func TestGenerateServerCertificate_PrivateKeyIsRSA(t *testing.T) {
	t.Parallel()

	cm, _ := newTestManager(t)
	cert, err := cm.generateServerCertificate("rsakey.example.com")
	require.NoError(t, err)

	_, ok := cert.PrivateKey.(*rsa.PrivateKey)
	assert.True(t, ok, "server cert private key must be RSA")
}

// ----- CA certificate properties -----

func TestCAProperties_Organization(t *testing.T) {
	t.Parallel()

	cm, _ := newTestManager(t)
	assert.Contains(t, cm.caCert.Subject.Organization, "coder")
}

func TestCAProperties_SerialNumber(t *testing.T) {
	t.Parallel()

	cm, _ := newTestManager(t)
	assert.Equal(t, big.NewInt(1), cm.caCert.SerialNumber,
		"CA serial number must be 1")
}

func TestCAProperties_Validity(t *testing.T) {
	t.Parallel()

	cm, _ := newTestManager(t)
	assert.True(t, cm.caCert.NotBefore.Before(time.Now()))
	assert.True(t, cm.caCert.NotAfter.After(time.Now()))

	// CA uses a 365-day validity window.
	expectedExpiry := time.Now().Add(365 * 24 * time.Hour)
	assert.True(t, cm.caCert.NotAfter.Before(expectedExpiry.Add(time.Hour)),
		"CA NotAfter must be approximately 1 year from now")
}

func TestCAProperties_KeyUsage(t *testing.T) {
	t.Parallel()

	cm, _ := newTestManager(t)
	assert.NotZero(t, cm.caCert.KeyUsage&x509.KeyUsageCertSign,
		"CA must have CertSign key usage")
	assert.NotZero(t, cm.caCert.KeyUsage&x509.KeyUsageDigitalSignature,
		"CA must have DigitalSignature key usage")
	assert.NotZero(t, cm.caCert.KeyUsage&x509.KeyUsageKeyEncipherment,
		"CA must have KeyEncipherment key usage")
}

func TestCAProperties_ExtKeyUsage(t *testing.T) {
	t.Parallel()

	cm, _ := newTestManager(t)
	assert.Contains(t, cm.caCert.ExtKeyUsage, x509.ExtKeyUsageServerAuth,
		"CA must have ServerAuth extended key usage")
}

// ----- Regeneration after corruption -----

func TestRegeneratesCA_WhenFilesCorrupted(t *testing.T) {
	t.Parallel()

	cfg := newTestConfig(t)

	// First call generates valid files.
	cm1, err := NewCertificateManager(cfg)
	require.NoError(t, err)

	// Corrupt both files.
	keyPath := filepath.Join(cfg.ConfigDir, config.CAKeyName)
	certPath := filepath.Join(cfg.ConfigDir, config.CACertName)
	require.NoError(t, os.WriteFile(keyPath, []byte("corrupted"), 0600))
	require.NoError(t, os.WriteFile(certPath, []byte("corrupted"), 0644))

	// Second call should regenerate (loadExistingCA fails, generateCA runs).
	cm2, err := NewCertificateManager(cfg)
	require.NoError(t, err)
	require.NotNil(t, cm2.caCert)
	require.NotNil(t, cm2.caKey)

	// The new CA should be different from the original.
	assert.NotEqual(t, cm1.caKey, cm2.caKey,
		"regenerated CA must use a new key")
}

// ----- certCache initialization -----

func TestCertCacheIsInitialized(t *testing.T) {
	t.Parallel()

	cm, _ := newTestManager(t)
	assert.NotNil(t, cm.certCache, "certCache must be initialized on creation")
	assert.Empty(t, cm.certCache, "certCache must start empty")
}

// ----- readerForTest helper for expired cert generation -----

// readerForTest returns a reader suitable for crypto operations.
// We use crypto/rand in production; tests reuse it.
func readerForTest() interface{ Read([]byte) (int, error) } {
	return realRandReader{}
}

type realRandReader struct{}

func (realRandReader) Read(p []byte) (int, error) {
	return rand.Read(p)
}
