package myip_test

import (
	"testing"

	"github.com/EdgarOrtegaRamirez/netprobe/pkg/myip"
)

func TestMyIPDetection(t *testing.T) {
	ipv4, ipv6, err := myip.Detect()
	if err != nil {
		// Network-dependent, skip
		t.Skipf("network-dependent test skipped: %v", err)
	}

	if ipv4 == "" && ipv6 == "" {
		t.Error("expected at least one IP address")
	}

	if ipv4 != "" {
		t.Logf("Detected IPv4: %s", ipv4)
	}
	if ipv6 != "" {
		t.Logf("Detected IPv6: %s", ipv6)
	}
}
