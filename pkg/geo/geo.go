package geo

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"time"
)

// GeoResult holds the geolocation lookup result.
type GeoResult struct {
	IP          string  `json:"ip"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	RegionName  string  `json:"region_name"`
	City        string  `json:"city"`
	ZIP         string  `json:"zip"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	Timezone    string  `json:"timezone"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	AS          string  `json:"as"`
	QueryIP     string  `json:"-"`
}

// ipAPIResponse maps the ip-api.com JSON response.
type ipAPIResponse struct {
	Status      string  `json:"status"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	RegionName  string  `json:"regionName"`
	City        string  `json:"city"`
	ZIP         string  `json:"zip"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	Timezone    string  `json:"timezone"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	AS          string  `json:"as"`
	Query       string  `json:"query"`
	Message     string  `json:"message,omitempty"`
}

var httpClient = &http.Client{
	Timeout: 10 * time.Second,
}

// Lookup performs a geolocation lookup for the given IP address.
func Lookup(ip string) (*GeoResult, error) {
	// Validate the IP
	_, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}

	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query", ip)

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

	var apiResp ipAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if apiResp.Status == "fail" {
		return nil, fmt.Errorf("ip-api.com lookup failed: %s", apiResp.Message)
	}

	result := &GeoResult{
		IP:          ip,
		Country:     apiResp.Country,
		CountryCode: apiResp.CountryCode,
		RegionName:  apiResp.RegionName,
		City:        apiResp.City,
		ZIP:         apiResp.ZIP,
		Lat:         apiResp.Lat,
		Lon:         apiResp.Lon,
		Timezone:    apiResp.Timezone,
		ISP:         apiResp.ISP,
		Org:         apiResp.Org,
		AS:          apiResp.AS,
		QueryIP:     apiResp.Query,
	}

	return result, nil
}
