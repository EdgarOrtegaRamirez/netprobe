// Package dns provides DNS lookup functionality.
package dns

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/EdgarOrtegaRamirez/netprobe/pkg/models"
)

// Lookup performs a comprehensive DNS lookup for the given host.
func Lookup(host string, timeout time.Duration) models.DNSResult {
	start := time.Now()
	result := models.DNSResult{Host: host}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	resolver := net.DefaultResolver
	recordTypes := []string{"A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"}

	for _, rType := range recordTypes {
		records := lookupByType(ctx, resolver, host, rType)
		result.Records = append(result.Records, records...)
	}

	result.Duration = time.Since(start)
	return result
}

func lookupByType(ctx context.Context, resolver *net.Resolver, host, rType string) []models.DNSRecord {
	var records []models.DNSRecord

	switch rType {
	case "A":
		addrs, err := resolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil
		}
		for _, addr := range addrs {
			if addr.IP.To4() != nil {
				records = append(records, models.DNSRecord{
					Type:  "A",
					Name:  host,
					Value: addr.IP.String(),
				})
			}
		}

	case "AAAA":
		addrs, err := resolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil
		}
		for _, addr := range addrs {
			if addr.IP.To4() == nil {
				records = append(records, models.DNSRecord{
					Type:  "AAAA",
					Name:  host,
					Value: addr.IP.String(),
				})
			}
		}

	case "MX":
		mxs, err := resolver.LookupMX(ctx, host)
		if err != nil {
			return nil
		}
		for _, mx := range mxs {
			records = append(records, models.DNSRecord{
				Type:  "MX",
				Name:  host,
				Value: fmt.Sprintf("%s (priority %d)", mx.Host, mx.Pref),
			})
		}

	case "NS":
		nss, err := resolver.LookupNS(ctx, host)
		if err != nil {
			return nil
		}
		for _, ns := range nss {
			records = append(records, models.DNSRecord{
				Type:  "NS",
				Name:  host,
				Value: ns.Host,
			})
		}

	case "TXT":
		txts, err := resolver.LookupTXT(ctx, host)
		if err != nil {
			return nil
		}
		for _, txt := range txts {
			records = append(records, models.DNSRecord{
				Type:  "TXT",
				Name:  host,
				Value: txt,
			})
		}

	case "CNAME":
		cname, err := resolver.LookupCNAME(ctx, host)
		if err != nil {
			return nil
		}
		records = append(records, models.DNSRecord{
			Type:  "CNAME",
			Name:  host,
			Value: cname,
		})
	}

	return records
}

// ResolveHost resolves a hostname to IP addresses.
func ResolveHost(host string, timeout time.Duration) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	resolver := net.DefaultResolver
	addrs, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}

	var ips []string
	for _, addr := range addrs {
		ips = append(ips, addr.IP.String())
	}
	return ips, nil
}
