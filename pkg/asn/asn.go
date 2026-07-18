package asn

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// ASNResult holds the ASN lookup result.
type ASNResult struct {
	IP       string `json:"ip"`
	ASN      uint32 `json:"asn"`
	Org      string `json:"org"`
	CIDR     string `json:"cidr"`
	Country  string `json:"country"`
	Registry string `json:"registry"`
	Date     string `json:"date"`
}

type ipAPIASNResponse struct {
	Status  string `json:"status"`
	Query   string `json:"query"`
	ASNStr  string `json:"as"`
	Org     string `json:"org"`
	CIDR    string `json:"asname"`
	Country string `json:"country"`
	Message string `json:"message,omitempty"`
}

type teamCymruResponse struct {
	ASN      uint32 `json:"asn"`
	ASName   string `json:"as_name"`
	CIDR     string `json:"cidr"`
	Country  string `json:"country"`
	Registry string `json:"registry"`
	Date     string `json:"date"`
	IP       string `json:"ip"`
}

var httpClient = &http.Client{
	Timeout: 10 * time.Second,
}

// Lookup performs an ASN lookup for the given IP address.
func Lookup(ip string) (*ASNResult, error) {
	_, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}

	// Try ip-api.com first (free, no key required)
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,query,as,org,asname,country", ip)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("User-Agent", "netlens/1.0")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to query ip-api.com: %w", err)
	}
	defer resp.Body.Close()

	var apiResp ipAPIASNResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if apiResp.Status == "fail" {
		return nil, fmt.Errorf("ASN lookup failed: %s", apiResp.Message)
	}

	// Parse ASN from string (e.g., "AS13335" -> 13335)
	var asnNum uint64
	asnStr := strings.TrimPrefix(apiResp.ASNStr, "AS")
	asnNum, _ = strconv.ParseUint(asnStr, 10, 32)

	result := &ASNResult{
		IP:       ip,
		ASN:      uint32(asnNum),
		Org:      apiResp.Org,
		CIDR:     apiResp.CIDR,
		Country:  apiResp.Country,
		Registry: "arin", // default registry
		Date:     time.Now().Format("2006-01-02"),
	}

	return result, nil
}
