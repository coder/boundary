package tls

import (
	"crypto/rand"
	"crypto/rsa"
	cryptotls "crypto/tls"
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

	"github.com/coder/boundary/config"
	"github.com/stretchr/testify/require"
)

func TestNewCertificateManagerGeneratesCA(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cm := newTestCertificateManager(t, dir)

	require.NotNil(t, cm.caKey)
	require.NotNil(t, cm.caCert)
	require.True(t, cm.caCert.IsCA)
	require.Equal(t, "coder CA", cm.caCert.Subject.CommonName)
	require.WithinDuration(t, time.Now().Add(365*24*time.Hour), cm.caCert.NotAfter, 5*time.Minute)

	storedCert := readCertificateFile(t, filepath.Join(dir, config.CACertName))
	require.Equal(t, cm.caCert.Raw, storedCert.Raw)

	storedKey := readPrivateKeyFile(t, filepath.Join(dir, config.CAKeyName))
	require.Equal(t, cm.caKey.N, storedKey.N)
}

func TestNewCertificateManagerLoadsExistingCA(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	first := newTestCertificateManager(t, dir)
	second := newTestCertificateManager(t, dir)

	require.Equal(t, first.caCert.Raw, second.caCert.Raw)
	require.Equal(t, first.caKey.N, second.caKey.N)
}

func TestNewCertificateManagerRegeneratesExpiredCA(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	expiredCert := writeExpiredCA(t, dir)

	cm := newTestCertificateManager(t, dir)

	require.NotEqual(t, expiredCert.Raw, cm.caCert.Raw)
	require.True(t, cm.caCert.NotAfter.After(time.Now()))

	storedCert := readCertificateFile(t, filepath.Join(dir, config.CACertName))
	require.Equal(t, cm.caCert.Raw, storedCert.Raw)
}

func TestSetupTLSAndWriteCACert(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cm := newTestCertificateManager(t, dir)

	certPath := filepath.Join(dir, config.CACertName)
	require.NoError(t, os.WriteFile(certPath, []byte("corrupted"), 0o644))

	tlsConfig, err := cm.SetupTLSAndWriteCACert()
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)
	require.Equal(t, uint16(cryptotls.VersionTLS12), tlsConfig.MinVersion)
	require.NotNil(t, tlsConfig.GetCertificate)

	serverCert, err := tlsConfig.GetCertificate(&cryptotls.ClientHelloInfo{ServerName: "example.com"})
	require.NoError(t, err)

	leaf := readTLSCertificate(t, serverCert)
	require.Equal(t, "example.com", leaf.Subject.CommonName)
	require.Equal(t, []string{"example.com"}, leaf.DNSNames)

	roots := x509.NewCertPool()
	roots.AddCert(cm.caCert)
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "example.com"})
	require.NoError(t, err)

	storedCert := readCertificateFile(t, certPath)
	require.Equal(t, cm.caCert.Raw, storedCert.Raw)
}

func TestGetCertificateRequiresServerName(t *testing.T) {
	t.Parallel()

	cm := newTestCertificateManager(t, t.TempDir())

	cert, err := cm.getCertificate(&cryptotls.ClientHelloInfo{})
	require.Nil(t, cert)
	require.EqualError(t, err, "no server name provided")
}

func TestGetCertificateCachesCertificates(t *testing.T) {
	t.Parallel()

	cm := newTestCertificateManager(t, t.TempDir())

	first, err := cm.getCertificate(&cryptotls.ClientHelloInfo{ServerName: "example.com"})
	require.NoError(t, err)

	second, err := cm.getCertificate(&cryptotls.ClientHelloInfo{ServerName: "example.com"})
	require.NoError(t, err)

	third, err := cm.getCertificate(&cryptotls.ClientHelloInfo{ServerName: "api.example.com"})
	require.NoError(t, err)

	require.Same(t, first, second)
	require.NotSame(t, first, third)
	require.Len(t, cm.certCache, 2)
}

func TestGetCertificateConcurrentRequestsReuseCachedCertificate(t *testing.T) {
	t.Parallel()

	cm := newTestCertificateManager(t, t.TempDir())

	const workers = 16
	results := make(chan *cryptotls.Certificate, workers)
	errs := make(chan error, workers)
	var wg sync.WaitGroup

	for range workers {
		wg.Go(func() {
			cert, err := cm.getCertificate(&cryptotls.ClientHelloInfo{ServerName: "example.com"})
			if err != nil {
				errs <- err
				return
			}
			results <- cert
		})
	}

	wg.Wait()
	close(results)
	close(errs)

	for err := range errs {
		require.NoError(t, err)
	}

	var first *cryptotls.Certificate
	count := 0
	for cert := range results {
		count++
		if first == nil {
			first = cert
			continue
		}
		require.Same(t, first, cert)
	}

	require.NotNil(t, first)
	require.Equal(t, workers, count)
	require.Len(t, cm.certCache, 1)
}

func TestGenerateServerCertificateIncludesIPAddressSAN(t *testing.T) {
	t.Parallel()

	cm := newTestCertificateManager(t, t.TempDir())

	serverCert, err := cm.generateServerCertificate("127.0.0.1")
	require.NoError(t, err)

	leaf := readTLSCertificate(t, serverCert)
	require.Equal(t, "127.0.0.1", leaf.Subject.CommonName)
	require.Len(t, leaf.IPAddresses, 1)
	require.True(t, leaf.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")))
	require.NoError(t, leaf.VerifyHostname("127.0.0.1"))
}

func newTestCertificateManager(t *testing.T, dir string) *CertificateManager {
	t.Helper()

	cm, err := NewCertificateManager(Config{
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		ConfigDir: dir,
		Uid:       os.Getuid(),
		Gid:       os.Getgid(),
	})
	require.NoError(t, err)

	return cm
}

func writeExpiredCA(t *testing.T, dir string) *x509.Certificate {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"coder"},
			CommonName:   "expired coder CA",
		},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	storedKey := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	require.NoError(t, os.WriteFile(filepath.Join(dir, config.CAKeyName), storedKey, 0o600))

	storedCert := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	require.NoError(t, os.WriteFile(filepath.Join(dir, config.CACertName), storedCert, 0o644))

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

func readCertificateFile(t *testing.T, path string) *x509.Certificate {
	t.Helper()

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	block, _ := pem.Decode(data)
	require.NotNil(t, block)
	require.Equal(t, "CERTIFICATE", block.Type)

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	return cert
}

func readPrivateKeyFile(t *testing.T, path string) *rsa.PrivateKey {
	t.Helper()

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	block, _ := pem.Decode(data)
	require.NotNil(t, block)
	require.Equal(t, "RSA PRIVATE KEY", block.Type)

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err)

	return privateKey
}

func readTLSCertificate(t *testing.T, cert *cryptotls.Certificate) *x509.Certificate {
	t.Helper()

	require.NotNil(t, cert)
	require.NotEmpty(t, cert.Certificate)

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)

	return leaf
}
