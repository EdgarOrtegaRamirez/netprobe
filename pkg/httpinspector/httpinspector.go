// Package httpinspector provides HTTP inspection functionality.
package httpinspector

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/EdgarOrtegaRamirez/netprobe/pkg/models"
)

// Inspect performs an HTTP inspection of the given URL.
func Inspect(rawURL string, timeout time.Duration) models.HTTPResult {
	start := time.Now()
	result := models.HTTPResult{URL: rawURL}

	// Normalize URL
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
		result.URL = rawURL
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		result.Error = fmt.Sprintf("invalid URL: %v", err)
		result.Duration = time.Since(start)
		return result
	}

	result.TLSEnabled = parsedURL.Scheme == "https"

	// Create transport with TLS config
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
		},
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: timeout,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			// Record redirect hop
			result.RedirectChain = append(result.RedirectChain, models.RedirectHop{
				URL: req.URL.String(),
			})
			return nil
		},
	}

	resp, err := client.Get(rawURL)
	if err != nil {
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.StatusText = http.StatusText(resp.StatusCode)
	result.Headers = make(map[string]string)
	for key, values := range resp.Header {
		result.Headers[key] = strings.Join(values, "; ")
	}
	result.BodySize = resp.ContentLength

	// Get TLS info from connection
	if resp.TLS != nil {
		result.TLSVersion = tlsVersionName(resp.TLS.Version)
	}

	// Read a small portion to verify body is accessible
	_, err = io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		// Body read error is not critical
	}

	result.Duration = time.Since(start)
	return result
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}
