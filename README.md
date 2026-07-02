# NetProbe 🔍

A fast, focused network diagnostic toolkit for developers and sysadmins. Combines DNS lookup, port scanning, HTTP inspection, and TLS certificate checking in a single Go binary.

## Features

- **DNS Lookup** — Comprehensive DNS record queries (A, AAAA, MX, NS, TXT, CNAME)
- **Port Scanning** — TCP port scan with concurrent workers, service detection, and banner grabbing
- **HTTP Inspection** — Inspect endpoints with status codes, headers, redirect chains, and TLS info
- **TLS Certificate Check** — Certificate details, expiry monitoring, chain validation, SANs
- **Batch Monitoring** — Check multiple hosts from a file, get expiry reports
- **Multiple Formats** — Text (human-readable) and JSON output

## Install

```bash
# From source
go install github.com/EdgarOrtegaRamirez/netprobe/cmd/netprobe@latest

# Or build locally
git clone https://github.com/EdgarOrtegaRamirez/netprobe.git
cd netprobe
go build -o netprobe ./cmd/netprobe/
```

## Quick Start

```bash
# DNS lookup
netprobe dns google.com

# Scan common ports
netprobe scan 192.168.1.1

# Scan specific ports
netprobe scan 192.168.1.1 -p 22,80,443,8080-8100

# Inspect an HTTP endpoint
netprobe http https://httpbin.org/get

# Check TLS certificate
netprobe tls google.com

# Batch certificate monitoring
netprobe tls --file hosts.txt --warn-days 30

# JSON output
netprobe dns google.com -f json
```

## Commands

### `dns <host>`
Perform comprehensive DNS lookup.

```bash
$ netprobe dns example.com
Host:      example.com
Duration:  12.3ms

Records (5):
TYPE   NAME          VALUE
----   ----          -----
A      example.com   93.184.216.34
AAAA   example.com   2606:2800:220:1:248:1893:25c8:1946
MX     example.com   mail.example.com (priority 10)
NS     example.com   a.iana-servers.net.
NS     example.com   b.iana-servers.net.
```

### `scan <host>`
TCP port scan with concurrent workers.

```bash
$ netprobe scan 192.168.1.1 -p 22,80,443
Host:      192.168.1.1
Duration:  1.2s

Open Ports (2):
PORT   STATE   SERVICE   BANNER
----   -----   -------   ------
22     open    SSH       SSH-2.0-OpenSSH_8.9
443    open    HTTPS
```

### `http <url>`
Inspect HTTP/HTTPS endpoints.

```bash
$ netprobe http https://httpbin.org/get
URL:          https://httpbin.org/get
Status:       200 OK
TLS:          true
TLS Version:  TLS 1.3
Body Size:    271 bytes
Duration:     45ms

Headers:
  Content-Type:   application/json
  Server:         gunicorn/19.9.0
```

### `tls <host>`
Check TLS certificate details and expiry.

```bash
$ netprobe tls google.com
Host:         google.com:443
Subject:      *.google.com
Issuer:       WR2
Valid Until:  2026-09-07 08:38:56 UTC
Days Left:    66
Key:          ECDSA 256-bit
Chain Valid:  true

Subject Alternative Names (65):
  - *.google.com
  - google.com
  - youtube.com
  - ...
```

### `tls --file <hosts.txt>`
Batch certificate monitoring with expiry report.

```bash
$ netprobe tls --file hosts.txt --warn-days 30
Certificate Expiry Report
============================================================
Warn threshold: 30 days

HOST                          DAYS LEFT   STATUS   ISSUER
----                          ---------   ------   ------
google.com:443                66          OK       WR2
expired.badssl.com:443        -120        EXPIRED  ...
self-signed.badssl.com:443    365         OK       ...
```

## Configuration

### Global Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-t, --timeout` | `10s` | Connection timeout |
| `-w, --workers` | `50` | Max concurrent workers (port scan) |
| `-f, --format` | `text` | Output format: `text` or `json` |

### Scan-Specific Flags

| Command | Flag | Default | Description |
|---------|------|---------|-------------|
| `scan` | `-p, --ports` | Common ports | Ports to scan |
| `tls` | `-p, --port` | `443` | Port number |
| `tls` | `--file` | — | Hosts file for batch check |

## Architecture

```
netprobe/
├── cmd/netprobe/          # CLI entry point (Cobra)
├── pkg/
│   ├── models/            # Data structures for results
│   ├── dns/               # DNS lookup module
│   ├── portscan/          # TCP port scanner
│   ├── httpinspector/     # HTTP inspection
│   ├── tlscheck/          # TLS certificate checker
│   └── output/            # Formatted output (text/JSON)
├── go.mod
├── go.sum
└── README.md
```

## Development

```bash
# Run tests
go test ./... -v

# Build
go build -o netprobe ./cmd/netprobe/

# Vet
go vet ./...
```

## License

MIT
