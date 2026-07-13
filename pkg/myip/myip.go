package myip

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var httpClient = &http.Client{
	Timeout: 10 * time.Second,
}

// Providers for detecting public IP
var ipv4Providers = []string{
	"https://api.ipify.org",
	"https://ipv4.icanhazip.com",
	"https://checkip.amazonaws.com",
}

var ipv6Providers = []string{
	"https://api6.ipify.org",
	"https://ipv6.icanhazip.com",
}

// Detect finds the public IPv4 and IPv6 addresses.
func Detect() (ipv4 string, ipv6 string, err error) {
	// Try each provider for IPv4
	for _, provider := range ipv4Providers {
		if ip, e := queryProvider(provider); e == nil && ip != "" {
			ipv4 = ip
			break
		}
	}

	// Try each provider for IPv6
	for _, provider := range ipv6Providers {
		if ip, e := queryProvider(provider); e == nil && ip != "" {
			ipv6 = ip
			break
		}
	}

	if ipv4 == "" && ipv6 == "" {
		return "", "", fmt.Errorf("could not detect public IP from any provider")
	}

	return ipv4, ipv6, nil
}

func queryProvider(url string) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "netlens/1.0")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	ip := strings.TrimSpace(string(body))
	if ip == "" {
		return "", fmt.Errorf("empty response from %s", url)
	}

	return ip, nil
}
