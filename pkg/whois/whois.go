package whois

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// Lookup performs a WHOIS lookup for the given domain or IP.
// Requires the 'whois' system command.
func Lookup(query string) (string, error) {
	// Validate input to prevent command injection
	if strings.ContainsAny(query, "|;&$`(){}[]!<>") {
		return "", fmt.Errorf("invalid characters in query")
	}

	cmd := exec.Command("whois", query)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if stderr.Len() > 0 {
			return "", fmt.Errorf("whois command failed: %s", strings.TrimSpace(stderr.String()))
		}
		return "", fmt.Errorf("whois command failed: %w", err)
	}

	output := stdout.String()
	if strings.TrimSpace(output) == "" {
		return "", fmt.Errorf("no WHOIS data returned for %s", query)
	}

	return output, nil
}
