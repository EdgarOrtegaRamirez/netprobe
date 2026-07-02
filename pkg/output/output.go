// Package output provides formatted output for scan results.
package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/EdgarOrtegaRamirez/netprobe/pkg/models"
)

// Format is the output format type.
type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
)

// PrintDNSResult outputs DNS lookup results.
func PrintDNSResult(result models.DNSResult, format Format) {
	if format == FormatJSON {
		printJSON(result)
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Host:\t%s\n", result.Host)
	fmt.Fprintf(w, "Duration:\t%s\n", result.Duration)

	if result.Error != "" {
		fmt.Fprintf(w, "Error:\t%s\n", result.Error)
	}

	if len(result.Records) == 0 {
		fmt.Fprintln(w, "\nNo DNS records found.")
	} else {
		fmt.Fprintf(w, "\nRecords (%d):\n", len(result.Records))
		fmt.Fprintln(w, "TYPE\tNAME\tVALUE")
		fmt.Fprintln(w, "----\t----\t-----")
		for _, r := range result.Records {
			fmt.Fprintf(w, "%s\t%s\t%s\n", r.Type, r.Name, r.Value)
		}
	}
	w.Flush()
}

// PrintPortScanResult outputs port scan results.
func PrintPortScanResult(result models.PortScanResult, format Format) {
	if format == FormatJSON {
		printJSON(result)
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Host:\t%s\n", result.Host)
	fmt.Fprintf(w, "Duration:\t%s\n", result.Duration)

	if result.Error != "" {
		fmt.Fprintf(w, "Error:\t%s\n", result.Error)
	}

	fmt.Fprintf(w, "\nOpen Ports (%d):\n", len(result.Open))
	if len(result.Open) > 0 {
		fmt.Fprintln(w, "PORT\tSTATE\tSERVICE\tBANNER")
		fmt.Fprintln(w, "----\t-----\t-------\t------")
		for _, p := range result.Open {
			banner := p.Banner
			if len(banner) > 50 {
				banner = banner[:50] + "..."
			}
			fmt.Fprintf(w, "%d\t%s\t%s\t%s\n", p.Port, p.State, p.Service, banner)
		}
	} else {
		fmt.Fprintln(w, "  (none)")
	}

	if len(result.Filtered) > 0 {
		fmt.Fprintf(w, "\nFiltered Ports (%d):\n", len(result.Filtered))
		for _, p := range result.Filtered {
			fmt.Fprintf(w, "%d\t%s\n", p.Port, p.State)
		}
	}
	w.Flush()
}

// PrintHTTPResult outputs HTTP inspection results.
func PrintHTTPResult(result models.HTTPResult, format Format) {
	if format == FormatJSON {
		printJSON(result)
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "URL:\t%s\n", result.URL)
	fmt.Fprintf(w, "Status:\t%d %s\n", result.StatusCode, result.StatusText)
	fmt.Fprintf(w, "TLS:\t%v\n", result.TLSEnabled)
	if result.TLSVersion != "" {
		fmt.Fprintf(w, "TLS Version:\t%s\n", result.TLSVersion)
	}
	fmt.Fprintf(w, "Body Size:\t%d bytes\n", result.BodySize)
	fmt.Fprintf(w, "Duration:\t%s\n", result.Duration)

	if result.Error != "" {
		fmt.Fprintf(w, "Error:\t%s\n", result.Error)
	}

	if len(result.RedirectChain) > 0 {
		fmt.Fprintf(w, "\nRedirect Chain (%d hops):\n", len(result.RedirectChain))
		for i, hop := range result.RedirectChain {
			fmt.Fprintf(w, "  %d. %s\n", i+1, hop.URL)
		}
	}

	if len(result.Headers) > 0 {
		fmt.Fprintln(w, "\nHeaders:")
		for key, value := range result.Headers {
			if len(value) > 80 {
				value = value[:80] + "..."
			}
			fmt.Fprintf(w, "  %s:\t%s\n", key, value)
		}
	}
	w.Flush()
}

// PrintTLSCertResult outputs TLS certificate check results.
func PrintTLSCertResult(result models.TLSCertResult, format Format) {
	if format == FormatJSON {
		printJSON(result)
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Host:\t%s:%d\n", result.Host, result.Port)
	fmt.Fprintf(w, "Subject:\t%s\n", result.Subject)
	fmt.Fprintf(w, "Issuer:\t%s\n", result.Issuer)
	fmt.Fprintf(w, "Serial:\t%s\n", result.SerialNumber)
	fmt.Fprintf(w, "Valid From:\t%s\n", result.NotBefore.Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(w, "Valid Until:\t%s\n", result.NotAfter.Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(w, "Days Left:\t%d\n", result.DaysLeft)
	fmt.Fprintf(w, "Key:\t%s %d-bit\n", result.KeyType, result.KeyBits)
	fmt.Fprintf(w, "Signature:\t%s\n", result.SignatureAlgo)
	fmt.Fprintf(w, "Chain Valid:\t%v\n", result.ChainValid)
	fmt.Fprintf(w, "Duration:\t%s\n", result.Duration)

	if result.Error != "" {
		fmt.Fprintf(w, "Error:\t%s\n", result.Error)
	}

	if len(result.SANs) > 0 {
		fmt.Fprintf(w, "\nSubject Alternative Names (%d):\n", len(result.SANs))
		for _, san := range result.SANs {
			fmt.Fprintf(w, "  - %s\n", san)
		}
	}

	if len(result.ChainErrors) > 0 {
		fmt.Fprintf(w, "\nChain Errors:\n")
		for _, e := range result.ChainErrors {
			fmt.Fprintf(w, "  - %s\n", e)
		}
	}
	w.Flush()
}

// PrintExpiryReport outputs a batch expiry report.
func PrintExpiryReport(results []models.TLSCertResult, warnDays int, format Format) {
	if format == FormatJSON {
		printJSON(results)
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "Certificate Expiry Report")
	fmt.Fprintln(w, strings.Repeat("=", 60))
	fmt.Fprintf(w, "Warn threshold: %d days\n\n", warnDays)
	fmt.Fprintln(w, "HOST\tDAYS LEFT\tSTATUS\tISSUER")
	fmt.Fprintln(w, "----\t---------\t------\t------")

	for _, r := range results {
		status := "OK"
		if r.Error != "" {
			status = "ERROR"
		} else if r.DaysLeft <= 0 {
			status = "EXPIRED"
		} else if r.DaysLeft <= warnDays {
			status = "WARNING"
		}
		host := fmt.Sprintf("%s:%d", r.Host, r.Port)
		if len(host) > 30 {
			host = host[:30] + "..."
		}
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\n", host, r.DaysLeft, status, r.Issuer)
	}
	w.Flush()
}

func printJSON(v interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}
