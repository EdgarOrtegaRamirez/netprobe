package httpinspector_test

import (
	"testing"
	"time"

	"github.com/EdgarOrtegaRamirez/netprobe/pkg/httpinspector"
)

func TestInspect_HTTP(t *testing.T) {
	result := httpinspector.Inspect("http://httpbin.org/get", 10*time.Second)
	if result.URL == "" {
		t.Error("expected non-empty URL")
	}
	if result.Duration == 0 {
		t.Error("expected non-zero duration")
	}
	// httpbin should return 200
	if result.StatusCode != 200 {
		t.Errorf("expected status 200, got %d (error: %s)", result.StatusCode, result.Error)
	}
}

func TestInspect_HTTPS(t *testing.T) {
	result := httpinspector.Inspect("https://httpbin.org/get", 10*time.Second)
	if !result.TLSEnabled {
		t.Error("expected TLS enabled for HTTPS URL")
	}
	if result.StatusCode != 200 {
		t.Errorf("expected status 200, got %d (error: %s)", result.StatusCode, result.Error)
	}
}

func TestInspect_NoProtocol(t *testing.T) {
	result := httpinspector.Inspect("httpbin.org/get", 10*time.Second)
	if result.URL != "https://httpbin.org/get" {
		t.Errorf("expected URL to have https:// prefix, got %s", result.URL)
	}
}

func TestInspect_InvalidURL(t *testing.T) {
	result := httpinspector.Inspect("://invalid-url", 2*time.Second)
	if result.Error == "" {
		t.Error("expected error for invalid URL")
	}
}

func TestInspect_NonExistent(t *testing.T) {
	result := httpinspector.Inspect("https://this-host-does-not-exist-12345.example.com", 3*time.Second)
	if result.Error == "" {
		t.Error("expected error for non-existent host")
	}
}

func TestInspect_Redirect(t *testing.T) {
	// httpbin.org/redirect/2 should follow 2 redirects
	result := httpinspector.Inspect("http://httpbin.org/redirect/2", 10*time.Second)
	// Should either follow redirects or report them
	if result.Error != "" && result.StatusCode == 0 {
		t.Logf("Note: redirect test result: %s", result.Error)
	}
}
