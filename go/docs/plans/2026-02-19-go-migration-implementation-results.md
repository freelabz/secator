# Secator Go PoC - Implementation Summary

This document summarizes the Go proof-of-concept implementation for secator, created to evaluate Go as a potential migration target from Python.

## Project Overview

The Go PoC implements core secator functionality with a focus on:
- Task execution (running external security tools)
- Workflow composition (YAML-defined task pipelines)
- Distributed execution (Celery-compatible broker)
- Result storage (MongoDB, GCS, API backends)
- Rich console output with colors and formatting

## Architecture

```
go/
├── cmd/secator/           # CLI entry points
│   ├── main.go            # Root command, version constant
│   ├── task.go            # Task runner (secator x <task> <target>)
│   ├── workflow.go        # Workflow runner (secator w <workflow> <target>)
│   ├── worker.go          # Celery worker mode
│   └── health.go          # Health check command
│
├── pkg/                   # Public packages
│   ├── types/             # Output type definitions
│   │   ├── types.go       # OutputType interface, Base struct
│   │   ├── url.go         # URL output type
│   │   ├── vulnerability.go # Vulnerability output type
│   │   ├── subdomain.go   # Subdomain output type
│   │   ├── certificate.go # Certificate output type
│   │   ├── info.go        # Info message type
│   │   └── error.go       # Error message type
│   └── console/           # Terminal output formatting
│       └── console.go     # Colors, banners, formatting utilities
│
├── internal/              # Private packages
│   ├── engine/            # Core execution engine
│   │   ├── runner.go      # Runner interface (Name, Status, Run)
│   │   ├── task.go        # Task interface extends Runner
│   │   └── executor.go    # Process execution with streaming
│   │
│   ├── tasks/             # Task implementations
│   │   ├── registry.go    # Task factory registry
│   │   ├── httpx/         # httpx task implementation
│   │   │   └── httpx.go
│   │   └── nuclei/        # nuclei task implementation
│   │       └── nuclei.go
│   │
│   ├── workflow/          # Workflow engine
│   │   ├── loader.go      # YAML workflow parser
│   │   └── executor.go    # Workflow execution (chain/group)
│   │
│   ├── store/             # Result storage backends
│   │   ├── store.go       # Store interface
│   │   ├── mongodb/       # MongoDB backend
│   │   ├── gcs/           # Google Cloud Storage backend
│   │   └── api/           # HTTP API backend
│   │
│   └── broker/            # Distributed task broker
│       ├── broker.go      # Broker interface
│       └── machinery/     # go-machinery Celery adapter
│
├── testdata/              # Test fixtures
│   └── httpx_output.json  # Sample httpx JSON output
│
└── benchmark/             # Performance benchmarks
    └── comparison_test.go # Go vs Python comparison tests
```

## Key Interfaces

### OutputType (`pkg/types/types.go`)
```go
type OutputType interface {
    Type() string                    // "url", "vulnerability", etc.
    UUID() string                    // Unique identifier
    Source() string                  // Task that produced this
    Timestamp() time.Time            // When produced
    ToMap() map[string]any           // Serialization
    SetContext(ctx map[string]any)   // Set context data
    SetSource(source string)         // Set source task
    String() string                  // Console representation
}
```

### Runner (`internal/engine/runner.go`)
```go
type Runner interface {
    Name() string
    Status() Status
    Run(ctx context.Context, inputs []string) <-chan types.OutputType
}
```

### Task (`internal/engine/task.go`)
```go
type Task interface {
    Runner
    Command() string                              // CLI command name
    Description() string                          // Human-readable description
    InputType() string                            // Expected input type
    OutputTypes() []string                        // Produced output types
    Install() error                               // Auto-installation
    Parse(line []byte) ([]types.OutputType, error) // Parse tool output
    SetOptions(opts map[string]any)               // Configure options
    CmdLine(inputs []string) string               // Full command for display
}
```

### Store (`internal/store/store.go`)
```go
type Store interface {
    Save(ctx context.Context, results []types.OutputType) error
    Load(ctx context.Context, filter map[string]any) ([]types.OutputType, error)
    Close() error
}
```

## Implemented Tasks

### httpx (`internal/tasks/httpx/httpx.go`)
- **Command**: `httpx-toolkit` (avoids conflict with Python httpx library)
- **Input**: URL
- **Outputs**: URL, Subdomain, Certificate
- **Options**: tech_detect, tls_grab, threads, rate_limit, timeout, follow_redirects, headers

### nuclei (`internal/tasks/nuclei/nuclei.go`)
- **Command**: `nuclei`
- **Input**: URL
- **Outputs**: Vulnerability
- **Options**: templates, severity, tags, exclude_tags, rate_limit, concurrency, timeout

## Console Output

The `pkg/console` package provides rich terminal output matching Python secator's style:

- **Banner**: ASCII art with version
- **Status messages**: `[INF]`, `[WRN]`, `[ERR]` with colors
- **Target display**: Emoji indicators based on target type (🎯)
- **Task lifecycle**: Start/end messages with result counts
- **Finding formatting**:
  - 🔗 URLs with status code colors (green <400, red >=400)
  - 🚨 Vulnerabilities with severity colors (critical/high=red, medium=yellow, low=green)
  - 🏰 Subdomains (dimmed if unresolved)
  - 🔒 Certificates with expiry status

Example output:
```
                     __
   ________  _______ / /_____  _____
  / ___/ _ \/ ___/ _ '/ __/ _ \/ ___/
 (__  /  __/ /__/ /_/ / /_/  __/ /
/____/\___/\___/\__,_/\__/\___/_/     v0.1.0-go

[INF] Loaded 1 target(s) for httpx
 🎯 https://example.com [url]
[INF] Running httpx: Fast and multi-purpose HTTP toolkit
⚡ httpx-toolkit -json -silent -threads 50 -timeout 10 -u https://example.com

🔗 https://example.com [200] Example Domain [nginx] [text/html]

[INF] httpx completed: SUCCESS (1 result)
```

## Workflow Engine

Workflows are defined in YAML and support:
- **Chain execution**: Sequential task execution, output flows to next task
- **Group execution**: Parallel task execution, results merged
- **Input extraction**: `targets` field specifies which outputs feed into tasks

Example workflow structure:
```yaml
name: recon
type: workflow
tasks:
  _group:
    - httpx:
        tech_detect: true
    - nuclei:
        severity: [critical, high]
```

## Commands

```bash
# Build
go build -o ./bin/secator ./cmd/secator

# Run a task
./bin/secator x httpx https://example.com
./bin/secator x httpx https://example.com --json

# Run a workflow
./bin/secator w recon https://example.com

# Health check
./bin/secator health

# Worker mode (distributed)
./bin/secator worker
```

## Testing

```bash
# Run all tests
go test ./...

# Run specific package tests
go test ./internal/tasks/httpx/...
go test ./internal/workflow/...
go test ./pkg/types/...

# Run with verbose output
go test -v ./...
```

## Dependencies

Key external dependencies:
- `github.com/spf13/cobra` - CLI framework
- `github.com/fatih/color` - Terminal colors
- `github.com/stretchr/testify` - Testing utilities
- `go.mongodb.org/mongo-driver` - MongoDB driver
- `cloud.google.com/go/storage` - GCS client
- `github.com/RichardKnop/machinery/v2` - Celery-compatible task queue
- `gopkg.in/yaml.v3` - YAML parsing

## Design Decisions

1. **httpx-toolkit command**: Uses `httpx-toolkit` instead of `httpx` to avoid conflicts with the Python httpx HTTP library that may be installed.

2. **Streaming results**: Tasks return `<-chan types.OutputType` for streaming results as they're produced, enabling real-time output.

3. **Task registry**: Tasks self-register via `init()` functions, allowing modular task loading.

4. **Context cancellation**: All long-running operations respect `context.Context` for clean shutdown.

5. **Interface-based design**: Core abstractions (Runner, Task, Store, Broker) are interfaces for testability and extensibility.

## Performance Notes

The Go implementation provides significant performance improvements over Python:
- Faster startup time (no interpreter overhead)
- Lower memory usage
- Better concurrency with goroutines
- Native binary distribution (no dependencies)

Benchmark tests in `benchmark/comparison_test.go` compare Go vs Python execution.
