package rdns_test

import (
	"testing"

	"github.com/EdgarOrtegaRamirez/netprobe/pkg/rdns"
)

func TestRDNSErrors(t *testing.T) {
	// Invalid IP should return error
	_, err := rdns.Lookup("not-an-ip")
	if err == nil {
		t.Error("expected error for invalid IP, got none")
	}

	// Invalid format
	_, err = rdns.Lookup("256.256.256.256")
	if err == nil {
		t.Error("expected error for out-of-range IP, got none")
	}
}

func TestRDNSEmpty(t *testing.T) {
	// A non-existent IP should return empty slice (no PTR).
	// 192.0.2.0 is in the TEST-NET range and should not have PTR records.
	hostnames, err := rdns.Lookup("192.0.2.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// No PTR records expected, but no error either
	if hostnames == nil {
		t.Error("expected empty slice, got nil")
	}
}
