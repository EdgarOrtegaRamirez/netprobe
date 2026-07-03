package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/EdgarOrtegaRamirez/netprobe/pkg/dns"
	"github.com/EdgarOrtegaRamirez/netprobe/pkg/httpinspector"
	"github.com/EdgarOrtegaRamirez/netprobe/pkg/models"
	"github.com/EdgarOrtegaRamirez/netprobe/pkg/output"
	"github.com/EdgarOrtegaRamirez/netprobe/pkg/portscan"
	"github.com/EdgarOrtegaRamirez/netprobe/pkg/tlscheck"
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
		Long:  "A fast, focused CLI for network diagnostics — DNS lookup, port scanning, HTTP inspection, and TLS certificate checking.",
	}

	rootCmd.PersistentFlags().DurationVarP(&timeout, "timeout", "t", 10*time.Second, "connection timeout")
	rootCmd.PersistentFlags().IntVarP(&maxWorkers, "workers", "w", 50, "max concurrent workers for port scanning")
	rootCmd.PersistentFlags().StringVarP(&outFormat, "format", "f", "text", "output format (text|json)")

	rootCmd.AddCommand(dnsCmd())
	rootCmd.AddCommand(scanCmd())
	rootCmd.AddCommand(httpCmd())
	rootCmd.AddCommand(tlsCmd())
	rootCmd.AddCommand(versionCmd())

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
