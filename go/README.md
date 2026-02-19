# Secator Go Migration PoC

Proof of concept for migrating secator from Python to Go, using Machinery for distributed task execution.

## Project Structure

| Component | Location | Status |
|-----------|----------|--------|
| CLI (Cobra) | `cmd/secator/` | Complete |
| Output Types | `pkg/types/` | Complete |
| Engine Interfaces | `internal/engine/` | Complete |
| httpx + nuclei Tasks | `internal/tasks/` | Complete |
| Workflow Loader/Executor | `internal/workflow/` | Complete |
| Stores (MongoDB, GCS, API) | `internal/store/` | Complete |
| Machinery Broker | `internal/broker/` | Complete |
| Benchmarks | `benchmark/` | Complete |
| Integration Tests | `integration_test.go` | Complete |

## Quick Start

```bash
# Build
go build -o bin/secator ./cmd/secator

# Check help
./bin/secator --help

# Check installed tools
./bin/secator health

# Run httpx task
./bin/secator x httpx https://example.com --json

# Run workflow
./bin/secator w test_workflow https://example.com
```

## Compare with Python

```bash
./scripts/compare.sh https://httpbin.org/get httpx
```

## Run Tests

```bash
# All tests (short mode)
go test ./... -short

# Full integration tests (requires httpx/nuclei installed)
go test ./... -v

# Benchmarks
go test ./benchmark/... -bench=.
```

## Architecture

### Core Interfaces

- **OutputType** (`pkg/types/types.go`): Base interface for all output types (URL, Vulnerability, etc.)
- **Runner** (`internal/engine/runner.go`): Base interface for executable units
- **Task** (`internal/engine/task.go`): Extends Runner with CLI tool execution
- **Store** (`internal/store/store.go`): Interface for result persistence
- **Broker** (`internal/broker/broker.go`): Interface for distributed task execution

### Task Registration

Tasks self-register via `init()`:

```go
func init() {
    registry.Register("httpx", func() engine.Task { return &Httpx{} })
}
```

### Workflow Format

Compatible with Python secator YAML format:

```yaml
type: workflow
name: example
tasks:
  httpx:
    tech_detect: true

  _group/scan:
    nuclei:
      severity: [critical, high]
    katana:
      targets_:
        - url.url
```

## Success Criteria

| Criterion | Status |
|-----------|--------|
| Performance | Channel-based streaming, goroutines for parallelism |
| Code simplicity | Clean interfaces, Go idioms |
| Deployment | Single `go build` produces working binary |
| Output compatibility | JSON matches Python field-for-field |
| Workflow compatibility | Same YAML files work in both versions |
| Store compatibility | Same MongoDB schema, same API calls |

## Next Steps

To proceed with full migration:

1. Port remaining 40+ tasks incrementally
2. Wire worker command to Machinery broker
3. Add centralized configuration (`pkg/config/`)
4. Implement auto-installation for tasks
