package rdns

import (
	"fmt"
	"net"
	"net/netip"
)

// Lookup performs a reverse DNS (PTR) lookup for the given IP address.
func Lookup(ip string) ([]string, error) {
	_, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}

	names, err := net.LookupAddr(ip)
	if err != nil {
		// If there's no PTR record, return empty slice
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return []string{}, nil
		}
		return nil, fmt.Errorf("reverse DNS lookup failed: %w", err)
	}

	return names, nil
}
