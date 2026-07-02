package portscan_test

import (
	"testing"
	"time"

	"github.com/EdgarOrtegaRamirez/netprobe/pkg/portscan"
)

func TestParsePorts_Single(t *testing.T) {
	ports, err := portscan.ParsePorts("80")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 1 || ports[0] != 80 {
		t.Errorf("expected [80], got %v", ports)
	}
}

func TestParsePorts_Multiple(t *testing.T) {
	ports, err := portscan.ParsePorts("80,443,8080")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 3 {
		t.Fatalf("expected 3 ports, got %d", len(ports))
	}
	expected := []int{80, 443, 8080}
	for i, p := range ports {
		if p != expected[i] {
			t.Errorf("port %d: expected %d, got %d", i, expected[i], p)
		}
	}
}

func TestParsePorts_Range(t *testing.T) {
	ports, err := portscan.ParsePorts("80-83")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := []int{80, 81, 82, 83}
	if len(ports) != len(expected) {
		t.Fatalf("expected %d ports, got %d", len(expected), len(ports))
	}
	for i, p := range ports {
		if p != expected[i] {
			t.Errorf("port %d: expected %d, got %d", i, expected[i], p)
		}
	}
}

func TestParsePorts_Complex(t *testing.T) {
	ports, err := portscan.ParsePorts("22,80-82,443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := []int{22, 80, 81, 82, 443}
	if len(ports) != len(expected) {
		t.Fatalf("expected %d ports, got %d", len(expected), len(ports))
	}
	for i, p := range ports {
		if p != expected[i] {
			t.Errorf("port %d: expected %d, got %d", i, expected[i], p)
		}
	}
}

func TestParsePorts_Invalid(t *testing.T) {
	_, err := portscan.ParsePorts("abc")
	if err == nil {
		t.Error("expected error for invalid port")
	}
}

func TestParsePorts_OutOfRange(t *testing.T) {
	_, err := portscan.ParsePorts("70000")
	if err == nil {
		t.Error("expected error for out of range port")
	}
}

func TestParsePorts_InvalidRange(t *testing.T) {
	_, err := portscan.ParsePorts("80-70")
	if err == nil {
		t.Error("expected error for invalid range")
	}
}

func TestDefaultPorts(t *testing.T) {
	ports := portscan.DefaultPorts()
	if len(ports) == 0 {
		t.Error("expected non-empty default ports")
	}
	// Check some expected ports
	found := make(map[int]bool)
	for _, p := range ports {
		found[p] = true
	}
	for _, expected := range []int{22, 80, 443} {
		if !found[expected] {
			t.Errorf("expected port %d in defaults", expected)
		}
	}
}

func TestScan_QuickScan(t *testing.T) {
	// Quick scan of a few ports on localhost - just verifies the function works
	result := portscan.Scan("127.0.0.1", []int{1}, 1*time.Second, 5)
	if result.Host != "127.0.0.1" {
		t.Errorf("expected host 127.0.0.1, got %s", result.Host)
	}
	if result.Duration == 0 {
		t.Error("expected non-zero duration")
	}
}

func TestScan_DefaultPorts(t *testing.T) {
	// Scan with default ports on a host that won't have most open
	result := portscan.Scan("127.0.0.1", []int{}, 500*time.Millisecond, 10)
	if result.Host != "127.0.0.1" {
		t.Errorf("expected host 127.0.0.1, got %s", result.Host)
	}
}
