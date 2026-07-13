package asn_test

import (
	"testing"

	"github.com/EdgarOrtegaRamirez/netprobe/pkg/asn"
)

func TestASNInvalidIP(t *testing.T) {
	_, err := asn.Lookup("not-an-ip")
	if err == nil {
		t.Error("expected error for invalid IP, got none")
	}
}

func TestASNValidIP(t *testing.T) {
	// Test with Cloudflare DNS (AS13335)
	result, err := asn.Lookup("1.1.1.1")
	if err != nil {
		t.Skipf("network-dependent test skipped: %v", err)
	}

	if result != nil {
		if result.IP != "1.1.1.1" {
			t.Errorf("expected IP 1.1.1.1, got %s", result.IP)
		}
	}
}