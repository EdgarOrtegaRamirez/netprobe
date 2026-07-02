package models_test

import (
	"testing"
	"time"

	"github.com/EdgarOrtegaRamirez/netprobe/pkg/models"
)

func TestDefaultConfig(t *testing.T) {
	cfg := models.DefaultConfig()
	if cfg.Timeout != 10*time.Second {
		t.Errorf("expected 10s timeout, got %v", cfg.Timeout)
	}
	if cfg.MaxWorkers != 50 {
		t.Errorf("expected 50 workers, got %d", cfg.MaxWorkers)
	}
	if cfg.Verbose {
		t.Error("expected verbose=false")
	}
}

func TestDNSResult_Fields(t *testing.T) {
	result := models.DNSResult{
		Host: "example.com",
		Records: []models.DNSRecord{
			{Type: "A", Name: "example.com", Value: "93.184.216.34"},
		},
		Duration: 100 * time.Millisecond,
	}
	if result.Host != "example.com" {
		t.Error("wrong host")
	}
	if len(result.Records) != 1 {
		t.Error("expected 1 record")
	}
}

func TestPortScanResult_Fields(t *testing.T) {
	result := models.PortScanResult{
		Host: "localhost",
		Open: []models.PortInfo{
			{Port: 80, Protocol: "tcp", State: "open", Service: "HTTP"},
		},
		Duration: 50 * time.Millisecond,
	}
	if result.Host != "localhost" {
		t.Error("wrong host")
	}
	if len(result.Open) != 1 {
		t.Error("expected 1 open port")
	}
	if result.Open[0].Service != "HTTP" {
		t.Error("wrong service name")
	}
}

func TestHTTPResult_Fields(t *testing.T) {
	result := models.HTTPResult{
		URL:        "https://example.com",
		StatusCode: 200,
		StatusText: "OK",
		Headers:    map[string]string{"Content-Type": "text/html"},
		TLSEnabled: true,
		Duration:   200 * time.Millisecond,
	}
	if result.StatusCode != 200 {
		t.Error("wrong status code")
	}
	if !result.TLSEnabled {
		t.Error("expected TLS enabled")
	}
}

func TestTLSCertResult_Fields(t *testing.T) {
	now := time.Now()
	result := models.TLSCertResult{
		Host:      "example.com",
		Port:      443,
		Subject:   "example.com",
		Issuer:    "Let's Encrypt",
		DaysLeft:  30,
		KeyType:   "RSA",
		KeyBits:   2048,
		NotBefore: now.Add(-30 * 24 * time.Hour),
		NotAfter:  now.Add(30 * 24 * time.Hour),
	}
	if result.DaysLeft != 30 {
		t.Error("wrong days left")
	}
	if result.KeyType != "RSA" {
		t.Error("wrong key type")
	}
}
