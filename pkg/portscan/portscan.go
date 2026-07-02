// Package portscan provides TCP port scanning functionality.
package portscan

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/EdgarOrtegaRamirez/netprobe/pkg/models"
)

// Well-known service names for common ports.
var wellKnownPorts = map[int]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
	80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 993: "IMAPS",
	995: "POP3S", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
	6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}

// ParsePorts parses a port specification string (e.g., "80,443,8000-8100").
func ParsePorts(spec string) ([]int, error) {
	var ports []int
	parts := strings.Split(spec, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			rangeParts := strings.SplitN(part, "-", 2)
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid range: %s", part)
			}
			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid start port: %s", rangeParts[0])
			}
			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid end port: %s", rangeParts[1])
			}
			if start > end || start < 1 || end > 65535 {
				return nil, fmt.Errorf("invalid range: %d-%d", start, end)
			}
			for i := start; i <= end; i++ {
				ports = append(ports, i)
			}
		} else {
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", part)
			}
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("port out of range: %d", port)
			}
			ports = append(ports, port)
		}
	}
	return ports, nil
}

// DefaultPorts returns common ports to scan.
func DefaultPorts() []int {
	return []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995,
		3306, 3389, 5432, 6379, 8080, 8443, 27017}
}

// Scan performs a TCP port scan on the given host.
func Scan(host string, ports []int, timeout time.Duration, maxWorkers int) models.PortScanResult {
	start := time.Now()
	result := models.PortScanResult{Host: host}

	if len(ports) == 0 {
		ports = DefaultPorts()
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxWorkers)

	for _, port := range ports {
		wg.Add(1)
		sem <- struct{}{}

		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()

			info := scanPort(host, p, timeout)
			mu.Lock()
			switch info.State {
			case "open":
				result.Open = append(result.Open, info)
			case "filtered":
				result.Filtered = append(result.Filtered, info)
			}
			mu.Unlock()
		}(port)
	}

	wg.Wait()
	result.Duration = time.Since(start)
	return result
}

func scanPort(host string, port int, timeout time.Duration) models.PortInfo {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)

	info := models.PortInfo{
		Port:     port,
		Protocol: "tcp",
		Service:  getServiceName(port),
	}

	if err != nil {
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline") {
			info.State = "filtered"
		} else {
			info.State = "closed"
		}
		return info
	}

	info.State = "open"

	// Try to grab a banner
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err == nil && len(banner) > 0 {
		info.Banner = strings.TrimSpace(banner)
	}

	conn.Close()
	return info
}

func getServiceName(port int) string {
	if name, ok := wellKnownPorts[port]; ok {
		return name
	}
	return "unknown"
}
