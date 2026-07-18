package whois_test

import (
	"testing"

	"github.com/EdgarOrtegaRamirez/netprobe/pkg/whois"
)

func TestWhoisInputValidation(t *testing.T) {
	// Test command injection prevention
	dangerousInputs := []string{
		"example.com; rm -rf /",
		"example.com|whoami",
		"$(cat /etc/passwd)",
		"example.com`id`",
		"example.com&whoami",
	}

	for _, input := range dangerousInputs {
		_, err := whois.Lookup(input)
		if err == nil {
			t.Errorf("expected error for dangerous input: %s", input)
		}
	}
}

func TestWhoisEmptyInput(t *testing.T) {
	_, err := whois.Lookup("")
	if err == nil {
		t.Error("expected error for empty input")
	}
}
