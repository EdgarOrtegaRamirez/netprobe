package cidr_test

import (
	"testing"

	"github.com/EdgarOrtegaRamirez/netprobe/pkg/cidr"
)

func TestCIDRCalculate(t *testing.T) {
	tests := []struct {
		input       string
		network     string
		broadcast   string
		firstHost   string
		lastHost    string
		prefixLen   int
		usableHosts uint64
		version     string
		wantErr     bool
	}{
		{
			input:       "192.168.1.0/24",
			network:     "192.168.1.0",
			broadcast:   "192.168.1.255",
			firstHost:   "192.168.1.1",
			lastHost:    "192.168.1.254",
			prefixLen:   24,
			usableHosts: 254,
			version:     "IPv4",
			wantErr:     false,
		},
		{
			input:       "10.0.0.0/8",
			network:     "10.0.0.0",
			broadcast:   "10.255.255.255",
			firstHost:   "10.0.0.1",
			lastHost:    "10.255.255.254",
			prefixLen:   8,
			usableHosts: 16777214,
			version:     "IPv4",
			wantErr:     false,
		},
		{
			input:       "172.16.0.0/16",
			network:     "172.16.0.0",
			firstHost:   "172.16.0.1",
			lastHost:    "172.16.255.254",
			prefixLen:   16,
			version:     "IPv4",
			wantErr:     false,
		},
		{
			input:       "10.0.0.1/32",
			network:     "10.0.0.1",
			broadcast:   "10.0.0.1",
			firstHost:   "10.0.0.1",
			lastHost:    "10.0.0.1",
			prefixLen:   32,
			usableHosts: 1,
			version:     "IPv4",
			wantErr:     false,
		},
		{
			input:   "invalid",
			wantErr: true,
		},
		{
			input:   "192.168.1.0/33",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := cidr.Calculate(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Network != tt.network {
				t.Errorf("network = %q, want %q", result.Network, tt.network)
			}
			if tt.broadcast != "" && result.Broadcast != tt.broadcast {
				t.Errorf("broadcast = %q, want %q", result.Broadcast, tt.broadcast)
			}
			if tt.firstHost != "" && result.FirstHost != tt.firstHost {
				t.Errorf("firstHost = %q, want %q", result.FirstHost, tt.firstHost)
			}
			if tt.lastHost != "" && result.LastHost != tt.lastHost {
				t.Errorf("lastHost = %q, want %q", result.LastHost, tt.lastHost)
			}
			if result.PrefixLength != tt.prefixLen {
				t.Errorf("prefixLen = %d, want %d", result.PrefixLength, tt.prefixLen)
			}
			if tt.usableHosts > 0 && result.UsableHosts != tt.usableHosts {
				t.Errorf("usableHosts = %d, want %d", result.UsableHosts, tt.usableHosts)
			}
			if result.IPVersion != tt.version {
				t.Errorf("version = %q, want %q", result.IPVersion, tt.version)
			}
		})
	}
}

func TestCIDREdgeCases(t *testing.T) {
	// /0 for IPv4 - very large range
	result, err := cidr.Calculate("0.0.0.0/0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.TotalHosts == 0 {
		t.Error("expected large total hosts for /0")
	}

	// IPv6
	result, err = cidr.Calculate("::1/128")
	if err != nil {
		t.Fatalf("unexpected error for IPv6: %v", err)
	}
	if result.IPVersion != "IPv6" {
		t.Errorf("expected IPv6, got %s", result.IPVersion)
	}
}