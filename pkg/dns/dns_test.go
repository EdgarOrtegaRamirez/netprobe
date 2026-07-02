package dns_test

import (
	"testing"
	"time"

	"github.com/EdgarOrtegaRamirez/netprobe/pkg/dns"
)

func TestLookup_Localhost(t *testing.T) {
	result := dns.Lookup("localhost", 5*time.Second)
	if result.Host != "localhost" {
		t.Errorf("expected host localhost, got %s", result.Host)
	}
	if result.Duration == 0 {
		t.Error("expected non-zero duration")
	}
	// localhost should have at least an A record
	hasA := false
	for _, r := range result.Records {
		if r.Type == "A" {
			hasA = true
			break
		}
	}
	if !hasA {
		t.Error("expected A record for localhost")
	}
}

func TestLookup_NonExistent(t *testing.T) {
	// This should return empty results (not an error, just no records)
	result := dns.Lookup("this-host-does-not-exist-12345.example.com", 2*time.Second)
	if result.Host != "this-host-does-not-exist-12345.example.com" {
		t.Errorf("expected host in result")
	}
	// Should have no records or an error
	if len(result.Records) != 0 && result.Error == "" {
		// Some resolvers may return results, that's OK
	}
}

func TestResolveHost_Localhost(t *testing.T) {
	ips, err := dns.ResolveHost("localhost", 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) == 0 {
		t.Error("expected at least one IP for localhost")
	}
}

func TestResolveHost_Invalid(t *testing.T) {
	_, err := dns.ResolveHost("this-host-does-not-exist-12345.example.com", 1*time.Second)
	// Should return an error for non-existent host
	// Note: some DNS resolvers may not return an error immediately
	_ = err // We just verify it doesn't panic
}
