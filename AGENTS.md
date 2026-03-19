# AGENTS.md – Development Guidelines

## Project Overview
- **Repository:** `discover-internal-domain`
- **Language:** Go 1.26.1
- **Purpose:** Brute-force DNS enumeration for internal assets (wildcard detection, worker pools, checkpointing)
- **Entry point:** `main.go` (root package)

---

## Build & Run Commands

```bash
# Build
go build ./...

# Run
go run . -domain=example.com -maxlen=4 -workers=20

# Cross-compile
GOOS=linux GOARCH=amd64 go build -o dnsbrute .

# Clean
go clean -cache -testcache
```

## Testing

```bash
# All tests (no cache, shuffled)
go test ./... -count=1 -shuffle=on -v

# Single test by name
go test ./... -run ^TestFunctionName$ -v

# Coverage report
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out -o coverage.html

# Benchmarks
go test -bench=. -benchmem ./...
```

## Linting & Formatting

```bash
# Format (required before commit)
gofmt -s -w .

# Preferred: also fixes imports
go run golang.org/x/tools/cmd/goimports -w .

# Lint
golangci-lint run --out-format=colored-line-number
go vet ./...
```

## Code Style

### Import Organization (3 blocks, blank line between)
```go
import (
    "context"
    "fmt"
    "net"

    "github.com/spf13/pflag"
)
```

### Naming Conventions
| Element | Convention |
|---------|------------|
| Packages | lowercase, no underscores (`resolver`) |
| Exported | PascalCase (`GenerateCombinations`) |
| Local variables | camelCase (`maxLen`) |
| Constants | PascalCase (`DefaultTimeout`) |
| File names | snake_case (`resolver.go`) |
| Initialisms | uppercase (`DNS`, `IP`, `JSON`) |

### Error Handling
- Wrap errors: `return fmt.Errorf("lookup %s: %w", host, err)`
- Log non-fatal errors: `log.Printf("error: %v", err)`
- Use `errors.Is` / `errors.As` for inspection
- Exported errors: `var ErrNotFound = errors.New("not found")`

### Types & Structs
- Keep structs small, single responsibility
- Export fields only when necessary
- Use `context.Context` as first argument for I/O
- Configuration via `pflag` with struct tags

```go
type Config struct {
    Domain  string        `flag:"domain" description:"Base domain"`
    MaxLen  int           `flag:"maxlen" description:"Max length"`
    Timeout time.Duration `flag:"timeout" description:"Query timeout"`
}
```

## Concurrency Patterns
- Worker pools with bounded channels
- `sync.WaitGroup` for graceful shutdown
- Context deadlines on all I/O operations
- `net.Resolver{PreferGo: true}` for DNS queries
- Avoid global mutable state

## Security Guidelines
- Do NOT log IPs/hostnames at INFO level
- Validate all input flags (non-negative, reasonable bounds)
- Use `--max-combinations` to prevent resource exhaustion
- Write checkpoints atomically (temp + rename)
- Set checkpoint file permissions: `0600`

## Documentation
- Every exported function/type needs godoc comment
- Complex algorithms need complexity analysis
- Line length: ≤100 characters

---

## Cursor & Copilot Rules
None present. Reference this file if added later.

*Last updated: 2026-03-19*
