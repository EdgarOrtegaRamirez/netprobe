package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/EdgarOrtegaRamirez/netprobe/pkg/asn"
	"github.com/EdgarOrtegaRamirez/netprobe/pkg/cidr"
	"github.com/EdgarOrtegaRamirez/netprobe/pkg/dns"
	"github.com/EdgarOrtegaRamirez/netprobe/pkg/geo"
	"github.com/EdgarOrtegaRamirez/netprobe/pkg/httpinspector"
	"github.com/EdgarOrtegaRamirez/netprobe/pkg/models"
	"github.com/EdgarOrtegaRamirez/netprobe/pkg/myip"
	"github.com/EdgarOrtegaRamirez/netprobe/pkg/output"
	"github.com/EdgarOrtegaRamirez/netprobe/pkg/portscan"
	"github.com/EdgarOrtegaRamirez/netprobe/pkg/rdns"
	"github.com/EdgarOrtegaRamirez/netprobe/pkg/tlscheck"
	"github.com/EdgarOrtegaRamirez/netprobe/pkg/whois"
	"github.com/spf13/cobra"
)

var (
	timeout    time.Duration
	maxWorkers int
	outFormat  string
	warnDays   int
	tlsPort    int
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "netprobe",
		Short: "Network Diagnostic Toolkit",
		Long:  "A fast, focused CLI for network diagnostics — DNS lookup, port scanning, HTTP inspection, TLS certificate checking, IP geolocation, ASN lookup, WHOIS, CIDR calculations, and more.",
	}

	rootCmd.PersistentFlags().DurationVarP(&timeout, "timeout", "t", 10*time.Second, "connection timeout")
	rootCmd.PersistentFlags().IntVarP(&maxWorkers, "workers", "w", 50, "max concurrent workers for port scanning")
	rootCmd.PersistentFlags().StringVarP(&outFormat, "format", "f", "text", "output format (text|json)")

	rootCmd.AddCommand(dnsCmd())
	rootCmd.AddCommand(scanCmd())
	rootCmd.AddCommand(httpCmd())
	rootCmd.AddCommand(tlsCmd())
	rootCmd.AddCommand(versionCmd())

	// netlens-ported commands
	rootCmd.AddCommand(geoCmd())
	rootCmd.AddCommand(asnCmdFunc())
	rootCmd.AddCommand(rdnsCmdFunc())
	rootCmd.AddCommand(whoisCmdFunc())
	rootCmd.AddCommand(cidrCmdFunc())
	rootCmd.AddCommand(myipCmdFunc())
	rootCmd.AddCommand(validateCmdFunc())
	rootCmd.AddCommand(bulkCmdFunc())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func getFormat() output.Format {
	if outFormat == "json" {
		return output.FormatJSON
	}
	return output.FormatText
}

// Helper: print any value as JSON
func printJSON(data interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(data)
}

func dnsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "dns <host>",
		Short: "DNS lookup",
		Long:  "Perform comprehensive DNS lookup for a hostname (A, AAAA, MX, NS, TXT, CNAME records).",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			host := args[0]
			result := dns.Lookup(host, timeout)
			output.PrintDNSResult(result, getFormat())
		},
	}
}

func scanCmd() *cobra.Command {
	var portsSpec string

	cmd := &cobra.Command{
		Use:   "scan <host>",
		Short: "Port scan",
		Long:  "TCP port scan with service detection and banner grabbing.",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			host := args[0]

			var ports []int
			if portsSpec != "" {
				var err error
				ports, err = portscan.ParsePorts(portsSpec)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error: %v\n", err)
					os.Exit(1)
				}
			}

			result := portscan.Scan(host, ports, timeout, maxWorkers)
			output.PrintPortScanResult(result, getFormat())
		},
	}

	cmd.Flags().StringVarP(&portsSpec, "ports", "p", "", "ports to scan (e.g., 80,443,8000-8100)")
	return cmd
}

func httpCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "http <url>",
		Short: "HTTP inspection",
		Long:  "Inspect HTTP/HTTPS endpoints — status, headers, redirects, TLS info.",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			rawURL := args[0]
			result := httpinspector.Inspect(rawURL, timeout)
			output.PrintHTTPResult(result, getFormat())
		},
	}
}

func tlsCmd() *cobra.Command {
	var hostsFile string

	cmd := &cobra.Command{
		Use:   "tls <host>",
		Short: "TLS certificate check",
		Long:  "Check TLS certificate details, expiry, chain validation, and SANs.",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if hostsFile != "" {
				runBatchTLS(hostsFile)
				return
			}
			if len(args) == 0 {
				fmt.Fprintln(os.Stderr, "Error: host argument required (or use --file)")
				os.Exit(1)
			}
			host := args[0]
			// Strip protocol prefix if present
			host = strings.TrimPrefix(host, "https://")
			host = strings.TrimPrefix(host, "http://")
			host = strings.TrimSuffix(host, "/")
			// Also strip port if embedded
			if idx := strings.LastIndex(host, ":"); idx != -1 {
				// Could be an IPv6 or a port
				rest := host[idx+1:]
				isPort := true
				for _, c := range rest {
					if c < '0' || c > '9' {
						isPort = false
						break
					}
				}
				if isPort {
					tlsPort = 0 // Will be set from flag
					host = host[:idx]
				}
			}

			if tlsPort == 0 {
				tlsPort = 443
			}
			if strings.Contains(args[0], ":443") {
				tlsPort = 443
			}

			result := tlscheck.Check(host, tlsPort, timeout)
			output.PrintTLSCertResult(result, getFormat())
		},
	}

	cmd.Flags().IntVarP(&tlsPort, "port", "p", 443, "port number")
	cmd.Flags().StringVar(&hostsFile, "file", "", "file with list of hosts (one per line)")
	return cmd
}

func runBatchTLS(hostsFile string) {
	data, err := os.ReadFile(hostsFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	hosts := strings.Split(string(data), "\n")
	var results []models.TLSCertResult

	for _, line := range hosts {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		h := line
		p := tlsPort
		// Parse host:port
		if idx := strings.LastIndex(h, ":"); idx != -1 {
			rest := h[idx+1:]
			isPort := true
			for _, c := range rest {
				if c < '0' || c > '9' {
					isPort = false
					break
				}
			}
			if isPort {
				p = 0
				fmt.Sscanf(rest, "%d", &p)
				h = h[:idx]
			}
		}
		if p == 0 {
			p = 443
		}

		result := tlscheck.Check(h, p, timeout)
		results = append(results, result)
	}

	output.PrintExpiryReport(results, warnDays, getFormat())
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("netprobe v1.0.0")
		},
	}
}

// ---------- netlens-ported commands ----------

func geoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "geo <ip-address>",
		Short: "IP geolocation lookup",
		Long:  `Look up the geographic location of an IP address. Returns country, city, region, coordinates, ISP, and timezone. Uses the ip-api.com free API.`,
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			ip := args[0]
			result, err := geo.Lookup(ip)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: geolocation lookup failed: %v\n", err)
				os.Exit(1)
			}
			if outFormat == "json" {
				format := getFormat()
				_ = format
				printJSON(result)
			} else {
				fmt.Printf("  IP:        %s\n", result.IP)
				fmt.Printf("  Country:   %s (%s)\n", result.Country, result.CountryCode)
				fmt.Printf("  Region:    %s\n", result.RegionName)
				fmt.Printf("  City:      %s\n", result.City)
				fmt.Printf("  ZIP:       %s\n", result.ZIP)
				fmt.Printf("  Lat/Lon:   %.4f / %.4f\n", result.Lat, result.Lon)
				fmt.Printf("  Timezone:  %s\n", result.Timezone)
				fmt.Printf("  ISP:       %s\n", result.ISP)
				fmt.Printf("  Org:       %s\n", result.Org)
				fmt.Printf("  AS:        %s\n", result.AS)
			}
		},
	}
}

func asnCmdFunc() *cobra.Command {
	return &cobra.Command{
		Use:   "asn <ip-address>",
		Short: "ASN lookup for an IP address",
		Long:  `Look up the Autonomous System Number (ASN) for an IP address. Returns the ASN number, organization name, and CIDR range.`,
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			ip := args[0]
			result, err := asn.Lookup(ip)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: ASN lookup failed: %v\n", err)
				os.Exit(1)
			}
			if outFormat == "json" {
				printJSON(result)
			} else {
				fmt.Printf("  IP:         %s\n", result.IP)
				fmt.Printf("  AS Number:  AS%d\n", result.ASN)
				fmt.Printf("  Org:        %s\n", result.Org)
				fmt.Printf("  CIDR:       %s\n", result.CIDR)
				fmt.Printf("  Country:    %s\n", result.Country)
				fmt.Printf("  Registry:   %s\n", result.Registry)
				fmt.Printf("  Date:       %s\n", result.Date)
			}
		},
	}
}

func rdnsCmdFunc() *cobra.Command {
	return &cobra.Command{
		Use:   "rdns <ip-address>",
		Short: "Reverse DNS (PTR) lookup",
		Long:  `Perform a reverse DNS lookup to find hostnames associated with an IP address.`,
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			ip := args[0]
			names, err := rdns.Lookup(ip)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: reverse DNS lookup failed: %v\n", err)
				os.Exit(1)
			}
			if outFormat == "json" {
				printJSON(names)
			} else {
				if len(names) == 0 {
					fmt.Printf("  No PTR records found for %s\n", ip)
				} else {
					fmt.Printf("  PTR records for %s:\n", ip)
					for _, name := range names {
						fmt.Printf("    %s\n", name)
					}
				}
			}
		},
	}
}

func whoisCmdFunc() *cobra.Command {
	return &cobra.Command{
		Use:   "whois <domain-or-ip>",
		Short: "WHOIS lookup",
		Long:  `Perform a WHOIS lookup for a domain name or IP address. Requires the 'whois' system command.`,
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			query := args[0]
			result, err := whois.Lookup(query)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: WHOIS lookup failed: %v\n", err)
				os.Exit(1)
			}
			if outFormat == "json" {
				printJSON(map[string]string{"query": query, "result": result})
			} else {
				fmt.Println(result)
			}
		},
	}
}

func cidrCmdFunc() *cobra.Command {
	return &cobra.Command{
		Use:   "cidr <cidr-notation>",
		Short: "CIDR calculator",
		Long:  `Calculate network information from a CIDR notation (e.g., 192.168.1.0/24). Returns network address, broadcast, host range, netmask, and more.`,
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cidrStr := args[0]
			result, err := cidr.Calculate(cidrStr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: CIDR calculation failed: %v\n", err)
				os.Exit(1)
			}
			if outFormat == "json" {
				printJSON(result)
			} else {
				fmt.Printf("  CIDR:         %s\n", result.CIDR)
				fmt.Printf("  IP:           %s\n", result.IP)
				fmt.Printf("  Netmask:      %s\n", result.Netmask)
				fmt.Printf("  Wildcard:     %s\n", result.Wildcard)
				fmt.Printf("  Network:      %s\n", result.Network)
				fmt.Printf("  Broadcast:    %s\n", result.Broadcast)
				fmt.Printf("  First Host:   %s\n", result.FirstHost)
				fmt.Printf("  Last Host:    %s\n", result.LastHost)
				fmt.Printf("  Total Hosts:  %d\n", result.TotalHosts)
				fmt.Printf("  Usable Hosts: %d\n", result.UsableHosts)
				fmt.Printf("  Prefix:       /%d\n", result.PrefixLength)
				fmt.Printf("  Version:      %s\n", result.IPVersion)
			}
		},
	}
}

func myipCmdFunc() *cobra.Command {
	return &cobra.Command{
		Use:   "myip",
		Short: "Detect public IP address",
		Long:  `Detect your public IPv4 and IPv6 addresses by querying external providers.`,
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			ipv4, ipv6, err := myip.Detect()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: could not detect public IP: %v\n", err)
				os.Exit(1)
			}
			if outFormat == "json" {
				printJSON(map[string]string{"ipv4": ipv4, "ipv6": ipv6})
			} else {
				if ipv4 != "" {
					fmt.Printf("  IPv4: %s\n", ipv4)
				}
				if ipv6 != "" {
					fmt.Printf("  IPv6: %s\n", ipv6)
				}
			}
		},
	}
}

func validateCmdFunc() *cobra.Command {
	return &cobra.Command{
		Use:   "validate <ip-address>",
		Short: "Validate an IP address",
		Long:  `Validate whether a string is a properly formatted IP address (IPv4 or IPv6).`,
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			ip := args[0]
			valid := false
			version := ""
			// Use netip from the geo package or stdlib to validate
			addr, err := netip.ParseAddr(ip)
			if err == nil {
				valid = true
				if addr.Is4() {
					version = "IPv4"
				} else if addr.Is6() {
					version = "IPv6"
				}
			}
			if outFormat == "json" {
				printJSON(map[string]interface{}{
					"ip":      ip,
					"valid":   valid,
					"version": version,
				})
			} else {
				if valid {
					fmt.Printf("  %s is a valid %s address\n", ip, version)
				} else {
					fmt.Printf("  %s is NOT a valid IP address\n", ip)
				}
			}
		},
	}
}

func bulkCmdFunc() *cobra.Command {
	return &cobra.Command{
		Use:   "bulk <file>",
		Short: "Bulk IP operations from file",
		Long:  `Process multiple IP addresses from a file, performing validation on each. Each line should contain one IP address. Lines starting with # are ignored.`,
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			filepath := args[0]
			f, err := os.Open(filepath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: could not open file: %v\n", err)
				os.Exit(1)
			}
			defer f.Close()

			type bulkEntry struct {
				IP      string `json:"ip"`
				Valid   bool   `json:"valid"`
				Version string `json:"version,omitempty"`
				Error   string `json:"error,omitempty"`
			}

			var results []bulkEntry
			var textLines []string

			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				entry := bulkEntry{IP: line}
				addr, err := netip.ParseAddr(line)
				if err != nil {
					entry.Error = err.Error()
				} else {
					entry.Valid = true
					if addr.Is4() {
						entry.Version = "IPv4"
					} else if addr.Is6() {
						entry.Version = "IPv6"
					}
				}
				results = append(results, entry)
				if entry.Valid {
					textLines = append(textLines, fmt.Sprintf("  %s — valid %s", entry.IP, entry.Version))
				} else {
					textLines = append(textLines, fmt.Sprintf("  %s — INVALID (%s)", entry.IP, entry.Error))
				}
			}

			if err := scanner.Err(); err != nil {
				fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
				os.Exit(1)
			}

			if outFormat == "json" {
				printJSON(results)
			} else {
				fmt.Printf("  Bulk validation results (%d entries):\n", len(results))
				for _, line := range textLines {
					fmt.Println(line)
				}
			}
		},
	}
}