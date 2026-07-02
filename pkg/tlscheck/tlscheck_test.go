package tlscheck_test

import (
	"testing"
	"time"

	"github.com/EdgarOrtegaRamirez/netprobe/pkg/tlscheck"
)

func TestCheck_HTTPS(t *testing.T) {
	result := tlscheck.Check("httpbin.org", 443, 10*time.Second)
	if result.Host != "httpbin.org" {
		t.Errorf("expected host httpbin.org, got %s", result.Host)
	}
	if result.Port != 443 {
		t.Errorf("expected port 443, got %d", result.Port)
	}
	if result.Error != "" {
		t.Fatalf("unexpected error: %s", result.Error)
	}
	if result.Subject == "" {
		t.Error("expected non-empty subject")
	}
	if result.Issuer == "" {
		t.Error("expected non-empty issuer")
	}
	if result.DaysLeft <= 0 {
		t.Errorf("expected positive days left, got %d", result.DaysLeft)
	}
	if result.Duration == 0 {
		t.Error("expected non-zero duration")
	}
}

func TestCheck_NonExistent(t *testing.T) {
	result := tlscheck.Check("this-host-does-not-exist-12345.example.com", 443, 3*time.Second)
	if result.Error == "" {
		t.Error("expected error for non-existent host")
	}
}

func TestCheck_WrongPort(t *testing.T) {
	// Port 1 is unlikely to have TLS
	result := tlscheck.Check("httpbin.org", 1, 3*time.Second)
	if result.Error == "" {
		t.Error("expected error for non-TLS port")
	}
}

func TestCheck_SelfSigned(t *testing.T) {
	// self-signed.badssl.com has a self-signed cert
	result := tlscheck.Check("self-signed.badssl.com", 443, 10*time.Second)
	if result.Error != "" {
		t.Logf("Note: self-signed test result: %s", result.Error)
	}
	// Chain should not be valid for self-signed
	if result.ChainValid {
		t.Error("expected chain to be invalid for self-signed cert")
	}
}

func TestCheck_Expired(t *testing.T) {
	// expired.badssl.com has an expired cert
	// Note: some networks may block/reset this connection
	result := tlscheck.Check("expired.badssl.com", 443, 10*time.Second)
	if result.Error != "" {
		t.Logf("Note: expired test result (may be network-blocked): %s", result.Error)
		return // Skip further checks if connection failed
	}
	// Should still return cert info
	if result.NotAfter.IsZero() {
		t.Error("expected non-zero NotAfter even for expired cert")
	}
}
