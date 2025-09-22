package dns

import (
	"os/exec"
	"testing"
)

func TestDNSWithCurl(t *testing.T) {
	out, err := exec.Command("curl", "--doh-url", "https://dns.google/dns-query", "http://coder.com", "-v").Output()
	if err != nil {
		t.Fatalf("error curling: %s", err)
	}
	t.Logf("output: %s", out)
}