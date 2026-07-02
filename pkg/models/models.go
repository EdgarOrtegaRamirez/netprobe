package models

import "time"

// DNSResult holds DNS lookup results.
type DNSResult struct {
	Host      string         `json:"host"`
	Records   []DNSRecord    `json:"records"`
	Duration  time.Duration  `json:"duration_ns"`
	Error     string         `json:"error,omitempty"`
}

// DNSRecord is a single DNS record.
type DNSRecord struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl"`
}

// PortScanResult holds port scanning results.
type PortScanResult struct {
	Host      string        `json:"host"`
	Open      []PortInfo    `json:"open_ports"`
	Filtered  []PortInfo    `json:"filtered_ports"`
	Duration  time.Duration `json:"duration_ns"`
	Error     string        `json:"error,omitempty"`
}

// PortInfo describes a single port.
type PortInfo struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Service  string `json:"service"`
	Banner   string `json:"banner,omitempty"`
}

// HTTPResult holds HTTP inspection results.
type HTTPResult struct {
	URL           string            `json:"url"`
	StatusCode    int               `json:"status_code"`
	StatusText    string            `json:"status_text"`
	Headers       map[string]string `json:"headers"`
	RedirectChain []RedirectHop     `json:"redirect_chain,omitempty"`
	BodySize      int64             `json:"body_size"`
	TLSEnabled    bool              `json:"tls_enabled"`
	TLSVersion    string            `json:"tls_version,omitempty"`
	Duration      time.Duration     `json:"duration_ns"`
	Error         string            `json:"error,omitempty"`
}

// RedirectHop is a single redirect in the chain.
type RedirectHop struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
}

// TLSCertResult holds TLS certificate check results.
type TLSCertResult struct {
	Host          string        `json:"host"`
	Port          int           `json:"port"`
	Issuer        string        `json:"issuer"`
	Subject       string        `json:"subject"`
	SANs          []string      `json:"sans"`
	SerialNumber  string        `json:"serial_number"`
	NotBefore     time.Time     `json:"not_before"`
	NotAfter      time.Time     `json:"not_after"`
	DaysLeft      int           `json:"days_left"`
	KeyType       string        `json:"key_type"`
	KeyBits       int           `json:"key_bits"`
	SignatureAlgo string        `json:"signature_algo"`
	ChainValid    bool          `json:"chain_valid"`
	ChainErrors   []string      `json:"chain_errors,omitempty"`
	Duration      time.Duration `json:"duration_ns"`
	Error         string        `json:"error,omitempty"`
}

// ScanConfig holds global scan configuration.
type ScanConfig struct {
	Timeout    time.Duration
	MaxWorkers int
	Verbose    bool
}

// DefaultConfig returns a sensible default configuration.
func DefaultConfig() ScanConfig {
	return ScanConfig{
		Timeout:    10 * time.Second,
		MaxWorkers: 50,
		Verbose:    false,
	}
}
