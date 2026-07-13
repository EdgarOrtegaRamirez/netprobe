package cidr

import (
	"fmt"
	"math"
	"net"
	"net/netip"
)

// CIDRResult holds the CIDR calculation result.
type CIDRResult struct {
	CIDR         string `json:"cidr"`
	IP           string `json:"ip"`
	Netmask      string `json:"netmask"`
	Wildcard     string `json:"wildcard"`
	Network      string `json:"network"`
	Broadcast    string `json:"broadcast"`
	FirstHost    string `json:"first_host"`
	LastHost     string `json:"last_host"`
	TotalHosts   uint64 `json:"total_hosts"`
	UsableHosts  uint64 `json:"usable_hosts"`
	PrefixLength int    `json:"prefix_length"`
	IPVersion    string `json:"ip_version"`
}

// Calculate computes network information from a CIDR notation.
func Calculate(cidrStr string) (*CIDRResult, error) {
	prefix, err := netip.ParsePrefix(cidrStr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR notation '%s': %w", cidrStr, err)
	}

	ip := prefix.Addr()
	ones := prefix.Bits()
	bits := ip.BitLen()

	// Convert to net.IP for binary operations
	ipNet := &net.IPNet{
		IP:   net.IP(ip.AsSlice()),
		Mask: net.CIDRMask(ones, bits),
	}

	// Calculate network address
	network := ipNet.IP.Mask(ipNet.Mask)

	// Calculate broadcast address
	broadcast := make(net.IP, len(network))
	for i := range network {
		broadcast[i] = network[i] | ^ipNet.Mask[i]
	}

	// Calculate netmask string
	netmask := net.IP(ipNet.Mask).String()

	// Calculate wildcard
	wildcard := make(net.IP, len(ipNet.Mask))
	for i, m := range ipNet.Mask {
		wildcard[i] = ^m
	}

	// Calculate total and usable hosts
	var totalHosts uint64
	var usableHosts uint64
	hostBits := bits - ones

	if hostBits < 0 {
		return nil, fmt.Errorf("prefix length /%d is too large for %d-bit address", ones, bits)
	}

	if hostBits >= 64 {
		// For very large ranges (e.g., /0 for IPv4 or /0-/64 for IPv6)
		totalHosts = math.MaxUint64
		usableHosts = math.MaxUint64
	} else {
		totalHosts = 1 << uint(hostBits)
		if totalHosts >= 2 {
			usableHosts = totalHosts - 2
		} else {
			usableHosts = totalHosts
		}
	}

	version := "IPv4"
	if bits == 128 {
		version = "IPv6"
	}

	// Calculate first and last usable hosts
	var firstHost, lastHost string
	if totalHosts >= 2 {
		firstHostIP := make(net.IP, len(network))
		lastHostIP := make(net.IP, len(network))
		copy(firstHostIP, network)
		copy(lastHostIP, broadcast)

		// First usable is network + 1
		for i := len(firstHostIP) - 1; i >= 0; i-- {
			firstHostIP[i]++
			if firstHostIP[i] != 0 {
				break
			}
		}

		// Last usable is broadcast - 1
		for i := len(lastHostIP) - 1; i >= 0; i-- {
			lastHostIP[i]--
			if lastHostIP[i] != 255 {
				break
			}
		}

		firstHost = firstHostIP.String()
		lastHost = lastHostIP.String()
	} else if totalHosts == 1 {
		// /32 for IPv4 or /128 for IPv6 — single host
		firstHost = ip.String()
		lastHost = ip.String()
	}

	result := &CIDRResult{
		CIDR:         cidrStr,
		IP:           ip.String(),
		Netmask:      netmask,
		Wildcard:     wildcard.String(),
		Network:      network.String(),
		Broadcast:    broadcast.String(),
		FirstHost:    firstHost,
		LastHost:     lastHost,
		TotalHosts:   totalHosts,
		UsableHosts:  usableHosts,
		PrefixLength: ones,
		IPVersion:    version,
	}

	return result, nil
}
