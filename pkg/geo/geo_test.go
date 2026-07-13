package geo_test

import (
	"testing"

	"github.com/EdgarOrtegaRamirez/netprobe/pkg/geo"
)

func TestGeoInvalidIP(t *testing.T) {
	_, err := geo.Lookup("not-an-ip")
	if err == nil {
		t.Error("expected error for invalid IP, got none")
	}

	_, err = geo.Lookup("999.999.999.999")
	if err == nil {
		t.Error("expected error for out-of-range IP, got none")
	}
}

func TestGeoValidIP(t *testing.T) {
	// Test with a known public DNS IP (Cloudflare)
	result, err := geo.Lookup("1.1.1.1")
	if err != nil {
		// Network-dependent, so skip instead of fail
		t.Skipf("network-dependent test skipped: %v", err)
	}

	if result != nil {
		if result.IP != "1.1.1.1" {
			t.Errorf("expected IP 1.1.1.1, got %s", result.IP)
		}
		if result.Country == "" {
			t.Error("expected non-empty country")
		}
	}
}