# AGENTS.md

## Project Overview

NetProbe is a network diagnostic toolkit written in Go. It provides DNS lookup, port scanning, HTTP inspection, TLS certificate checking, IP geolocation, ASN lookup, WHOIS queries, CIDR calculations, reverse DNS, and public IP detection — all in a single binary.

## Architecture

- `cmd/netprobe/main.go` — CLI entry point using Cobra
- `pkg/dns/` — DNS lookup functionality
- `pkg/portscan/` — TCP port scanning with concurrency
- `pkg/httpinspector/` — HTTP endpoint inspection
- `pkg/tlscheck/` — TLS certificate analysis
- `pkg/output/` — Formatted output (text and JSON)
- `pkg/models/` — Shared data structures
- `pkg/asn/` — ASN lookup via ip-api.com
- `pkg/cidr/` — CIDR calculator (pure Go)
- `pkg/geo/` — IP geolocation via ip-api.com
- `pkg/myip/` — Public IP detection
- `pkg/rdns/` — Reverse DNS (PTR lookup)
- `pkg/whois/` — WHOIS lookup (system command)

## Development

```bash
# Build
go build -o netprobe ./cmd/netprobe/

# Test
go test ./... -v

# Vet
go vet ./...

# Run
./netprobe dns example.com
./netprobe scan 127.0.0.1
./netprobe http https://example.com
./netprobe tls example.com
./netprobe geo 8.8.8.8
./netprobe asn 1.1.1.1
./netprobe cidr 192.168.1.0/24
./netprobe rdns 8.8.8.8
./netprobe whois example.com
./netprobe myip
./netprobe validate 192.168.1.1
```

## Key Design Decisions

1. **Standard library first** — Uses Go stdlib for networking (net, crypto/tls, net/http)
2. **Concurrent scanning** — Port scanner uses goroutine pool with semaphore
3. **Graceful timeouts** — All network operations respect configurable timeouts
4. **JSON output** — Every command supports `-f json` for scripting
5. **No external dependencies for core** — Only Cobra for CLI, everything else is stdlib

## Testing

Tests are in each package directory (e.g., `pkg/portscan/portscan_test.go`). Network tests may fail in restricted environments — that's expected.

## Dependencies

- `github.com/spf13/cobra` — CLI framework
- Go standard library for all networking

## Commands

| Command | Description |
|---------|-------------|
| dns <host> | DNS lookup (A, AAAA, MX, NS, TXT, CNAME) |
| scan <host> | TCP port scan with service detection |
| http <url> | HTTP endpoint inspection |
| tls <host> | TLS certificate check |
| geo <ip> | IP geolocation lookup |
| asn <ip> | ASN lookup |
| cidr <cidr> | CIDR calculator |
| rdns <ip> | Reverse DNS (PTR) lookup |
| whois <domain> | WHOIS lookup |
| myip | Detect public IP address |
| validate <ip> | Validate IP address format |
| bulk <file> | Bulk IP validation from file |
| version | Print version