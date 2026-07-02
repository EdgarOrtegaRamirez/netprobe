# AGENTS.md

## Project Overview

NetProbe is a network diagnostic toolkit written in Go. It provides DNS lookup, port scanning, HTTP inspection, and TLS certificate checking as a single binary.

## Architecture

- `cmd/netprobe/main.go` — CLI entry point using Cobra
- `pkg/models/` — Shared data structures
- `pkg/dns/` — DNS lookup functionality
- `pkg/portscan/` — TCP port scanning with concurrency
- `pkg/httpinspector/` — HTTP endpoint inspection
- `pkg/tlscheck/` — TLS certificate analysis
- `pkg/output/` — Formatted output (text and JSON)

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
