# Secator Go Migration PoC - Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a Go PoC that validates migrating secator from Python, demonstrating performance gains and deployment simplicity.

**Architecture:** Go-native design using channels for streaming, Machinery for distributed execution, and a clean Store interface for MongoDB/GCS/API backends.

**Tech Stack:** Go 1.21+, Cobra (CLI), Machinery (task queue), mongo-driver, cloud.google.com/go/storage

---

## Task 1: Project Scaffolding

**Files:**
- Create: `go/go.mod`
- Create: `go/go.sum`
- Create: `go/cmd/secator/main.go`
- Create: `go/.gitignore`

**Step 1: Initialize Go module**

```bash
cd /home/jahmyst/Workspace/secator
mkdir -p go/cmd/secator
cd go
go mod init github.com/freelabz/secator
```

**Step 2: Create minimal main.go**

```go
// go/cmd/secator/main.go
package main

import "fmt"

func main() {
	fmt.Println("secator-go")
}
```

**Step 3: Add .gitignore**

```gitignore
# go/.gitignore
/bin/
*.exe
*.exe~
*.dll
*.so
*.dylib
*.test
*.out
go.work
go.work.sum
```

**Step 4: Verify build works**

Run: `cd /home/jahmyst/Workspace/secator/go && go build -o bin/secator ./cmd/secator`
Expected: Binary created at `go/bin/secator`

Run: `./bin/secator`
Expected: Output `secator-go`

**Step 5: Commit**

```bash
git add go/
git commit -m "feat(go): initialize go module with minimal main"
```

---

## Task 2: Output Types - Base Interface

**Files:**
- Create: `go/pkg/types/types.go`
- Create: `go/pkg/types/types_test.go`

**Step 1: Write the failing test**

```go
// go/pkg/types/types_test.go
package types

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBaseType_ImplementsOutputType(t *testing.T) {
	var _ OutputType = &BaseType{}
}

func TestBaseType_Type(t *testing.T) {
	b := &BaseType{TypeName: "url"}
	assert.Equal(t, "url", b.Type())
}

func TestBaseType_UUID(t *testing.T) {
	b := &BaseType{}
	uuid := b.UUID()
	assert.NotEmpty(t, uuid)
	// UUID should be consistent
	assert.Equal(t, uuid, b.UUID())
}

func TestBaseType_ToMap(t *testing.T) {
	b := &BaseType{
		TypeName:   "url",
		SourceName: "httpx",
	}
	m := b.ToMap()
	assert.Equal(t, "url", m["_type"])
	assert.Equal(t, "httpx", m["_source"])
	assert.NotEmpty(t, m["_uuid"])
	assert.NotEmpty(t, m["_timestamp"])
}

func TestBaseType_SetContext(t *testing.T) {
	b := &BaseType{}
	ctx := map[string]any{"workspace": "test"}
	b.SetContext(ctx)
	assert.Equal(t, "test", b.Context["workspace"])
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/jahmyst/Workspace/secator/go && go mod tidy && go test ./pkg/types/... -v`
Expected: FAIL - package not found or types not defined

**Step 3: Write minimal implementation**

```go
// go/pkg/types/types.go
package types

import (
	"time"

	"github.com/google/uuid"
)

// OutputType is the base interface all findings implement
type OutputType interface {
	Type() string
	UUID() string
	Source() string
	Timestamp() time.Time
	ToMap() map[string]any
	SetContext(ctx map[string]any)
}

// BaseType provides common fields for all output types
type BaseType struct {
	TypeName   string         `json:"_type"`
	IDValue    string         `json:"_uuid"`
	SourceName string         `json:"_source"`
	Time       time.Time      `json:"_timestamp"`
	Context    map[string]any `json:"_context,omitempty"`
	Duplicate  bool           `json:"_duplicate,omitempty"`
}

func (b *BaseType) Type() string {
	return b.TypeName
}

func (b *BaseType) UUID() string {
	if b.IDValue == "" {
		b.IDValue = uuid.New().String()
	}
	return b.IDValue
}

func (b *BaseType) Source() string {
	return b.SourceName
}

func (b *BaseType) Timestamp() time.Time {
	if b.Time.IsZero() {
		b.Time = time.Now()
	}
	return b.Time
}

func (b *BaseType) ToMap() map[string]any {
	return map[string]any{
		"_type":      b.Type(),
		"_uuid":      b.UUID(),
		"_source":    b.Source(),
		"_timestamp": b.Timestamp(),
		"_context":   b.Context,
		"_duplicate": b.Duplicate,
	}
}

func (b *BaseType) SetContext(ctx map[string]any) {
	if b.Context == nil {
		b.Context = make(map[string]any)
	}
	for k, v := range ctx {
		b.Context[k] = v
	}
}

// SetSource sets the source name
func (b *BaseType) SetSource(source string) {
	b.SourceName = source
}
```

**Step 4: Run test to verify it passes**

Run: `cd /home/jahmyst/Workspace/secator/go && go mod tidy && go test ./pkg/types/... -v`
Expected: PASS

**Step 5: Commit**

```bash
git add go/
git commit -m "feat(go): add base OutputType interface and BaseType"
```

---

## Task 3: Output Types - URL Type

**Files:**
- Create: `go/pkg/types/url.go`
- Create: `go/pkg/types/url_test.go`
- Create: `go/testdata/httpx_output.json` (copy from Python fixtures)

**Step 1: Copy fixture**

```bash
cp /home/jahmyst/Workspace/secator/tests/fixtures/httpx_output.json /home/jahmyst/Workspace/secator/go/testdata/
```

**Step 2: Write the failing test**

```go
// go/pkg/types/url_test.go
package types

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestURL_ImplementsOutputType(t *testing.T) {
	var _ OutputType = &URL{}
}

func TestURL_Type(t *testing.T) {
	u := &URL{}
	assert.Equal(t, "url", u.Type())
}

func TestURL_ToMap(t *testing.T) {
	u := &URL{
		URL:          "https://example.com",
		Host:         "example.com",
		Port:         443,
		Scheme:       "https",
		StatusCode:   200,
		ContentType:  "text/html",
		Technologies: []string{"nginx"},
	}
	u.SetSource("httpx")

	m := u.ToMap()
	assert.Equal(t, "url", m["_type"])
	assert.Equal(t, "https://example.com", m["url"])
	assert.Equal(t, 200, m["status_code"])
	assert.Equal(t, []string{"nginx"}, m["technologies"])
}

func TestURL_ParseFromHTTPX(t *testing.T) {
	data, err := os.ReadFile("../../testdata/httpx_output.json")
	require.NoError(t, err)

	var raw map[string]any
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	url, err := URLFromMap(raw)
	require.NoError(t, err)

	assert.Equal(t, "https://media.example.synology.me:443", url.URL)
	assert.Equal(t, "82.61.151.800", url.Host)
	assert.Equal(t, 443, url.Port)
	assert.Equal(t, "https", url.Scheme)
	assert.Equal(t, 200, url.StatusCode)
	assert.Equal(t, "text/html", url.ContentType)
	assert.Contains(t, url.Technologies, "Nginx")
}
```

**Step 3: Run test to verify it fails**

Run: `cd /home/jahmyst/Workspace/secator/go && go test ./pkg/types/... -v`
Expected: FAIL - URL type not defined

**Step 4: Write minimal implementation**

```go
// go/pkg/types/url.go
package types

import (
	"fmt"
	"strconv"
)

// URL represents an HTTP URL finding
type URL struct {
	BaseType
	URL           string   `json:"url"`
	Host          string   `json:"host"`
	Port          int      `json:"port"`
	Scheme        string   `json:"scheme"`
	StatusCode    int      `json:"status_code"`
	ContentType   string   `json:"content_type"`
	ContentLength int      `json:"content_length"`
	Title         string   `json:"title,omitempty"`
	Webserver     string   `json:"webserver,omitempty"`
	Technologies  []string `json:"technologies,omitempty"`
	FinalURL      string   `json:"final_url,omitempty"`
}

func (u *URL) Type() string {
	return "url"
}

func (u *URL) ToMap() map[string]any {
	m := u.BaseType.ToMap()
	m["_type"] = "url"
	m["url"] = u.URL
	m["host"] = u.Host
	m["port"] = u.Port
	m["scheme"] = u.Scheme
	m["status_code"] = u.StatusCode
	m["content_type"] = u.ContentType
	m["content_length"] = u.ContentLength
	m["title"] = u.Title
	m["webserver"] = u.Webserver
	m["technologies"] = u.Technologies
	m["final_url"] = u.FinalURL
	return m
}

// URLFromMap creates a URL from a raw map (e.g., from httpx JSON)
func URLFromMap(raw map[string]any) (*URL, error) {
	u := &URL{}

	if v, ok := raw["url"].(string); ok {
		u.URL = v
	}
	if v, ok := raw["host"].(string); ok {
		u.Host = v
	}
	if v, ok := raw["port"].(string); ok {
		u.Port, _ = strconv.Atoi(v)
	} else if v, ok := raw["port"].(float64); ok {
		u.Port = int(v)
	}
	if v, ok := raw["scheme"].(string); ok {
		u.Scheme = v
	}
	if v, ok := raw["status_code"].(float64); ok {
		u.StatusCode = int(v)
	}
	if v, ok := raw["content_type"].(string); ok {
		u.ContentType = v
	}
	if v, ok := raw["content_length"].(float64); ok {
		u.ContentLength = int(v)
	}
	if v, ok := raw["title"].(string); ok {
		u.Title = v
	}
	if v, ok := raw["webserver"].(string); ok {
		u.Webserver = v
	}
	if v, ok := raw["tech"].([]any); ok {
		for _, t := range v {
			if s, ok := t.(string); ok {
				u.Technologies = append(u.Technologies, s)
			}
		}
	}
	if v, ok := raw["final_url"].(string); ok {
		u.FinalURL = v
	}

	// Extract port from URL if not set
	if u.Port == 0 && u.Scheme == "https" {
		u.Port = 443
	} else if u.Port == 0 && u.Scheme == "http" {
		u.Port = 80
	}

	if u.URL == "" {
		return nil, fmt.Errorf("url field is required")
	}

	return u, nil
}
```

**Step 5: Run test to verify it passes**

Run: `cd /home/jahmyst/Workspace/secator/go && go test ./pkg/types/... -v`
Expected: PASS

**Step 6: Commit**

```bash
git add go/
git commit -m "feat(go): add URL output type with httpx parsing"
```

---

## Task 4: Output Types - Vulnerability Type

**Files:**
- Create: `go/pkg/types/vulnerability.go`
- Create: `go/pkg/types/vulnerability_test.go`
- Create: `go/testdata/nuclei_output.json` (copy from Python fixtures)

**Step 1: Copy fixture**

```bash
cp /home/jahmyst/Workspace/secator/tests/fixtures/nuclei_output.json /home/jahmyst/Workspace/secator/go/testdata/
```

**Step 2: Write the failing test**

```go
// go/pkg/types/vulnerability_test.go
package types

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVulnerability_ImplementsOutputType(t *testing.T) {
	var _ OutputType = &Vulnerability{}
}

func TestVulnerability_Type(t *testing.T) {
	v := &Vulnerability{}
	assert.Equal(t, "vulnerability", v.Type())
}

func TestVulnerability_ParseFromNuclei(t *testing.T) {
	data, err := os.ReadFile("../../testdata/nuclei_output.json")
	require.NoError(t, err)

	var raw map[string]any
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	vuln, err := VulnerabilityFromMap(raw)
	require.NoError(t, err)

	assert.Equal(t, "HTTP Missing Security Headers", vuln.Name)
	assert.Equal(t, "info", vuln.Severity)
	assert.Equal(t, "https://example.synology.me", vuln.MatchedAt)
	assert.Equal(t, "80.32.101.118", vuln.IP)
	assert.Equal(t, "nuclei", vuln.Provider)
	assert.Equal(t, "http-missing-security-headers", vuln.TemplateID)
	assert.Contains(t, vuln.Tags, "misconfig")
}
```

**Step 3: Run test to verify it fails**

Run: `cd /home/jahmyst/Workspace/secator/go && go test ./pkg/types/... -v`
Expected: FAIL - Vulnerability type not defined

**Step 4: Write minimal implementation**

```go
// go/pkg/types/vulnerability.go
package types

import "fmt"

// Vulnerability represents a security vulnerability finding
type Vulnerability struct {
	BaseType
	Name        string   `json:"name"`
	Severity    string   `json:"severity"` // critical, high, medium, low, info
	MatchedAt   string   `json:"matched_at"`
	Host        string   `json:"host"`
	IP          string   `json:"ip"`
	Provider    string   `json:"provider"` // nuclei, sqlmap, etc.
	TemplateID  string   `json:"template_id,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	References  []string `json:"references,omitempty"`
	Description string   `json:"description,omitempty"`
	MatcherName string   `json:"matcher_name,omitempty"`
}

func (v *Vulnerability) Type() string {
	return "vulnerability"
}

func (v *Vulnerability) ToMap() map[string]any {
	m := v.BaseType.ToMap()
	m["_type"] = "vulnerability"
	m["name"] = v.Name
	m["severity"] = v.Severity
	m["matched_at"] = v.MatchedAt
	m["host"] = v.Host
	m["ip"] = v.IP
	m["provider"] = v.Provider
	m["template_id"] = v.TemplateID
	m["tags"] = v.Tags
	m["references"] = v.References
	m["description"] = v.Description
	m["matcher_name"] = v.MatcherName
	return m
}

// VulnerabilityFromMap creates a Vulnerability from nuclei JSON output
func VulnerabilityFromMap(raw map[string]any) (*Vulnerability, error) {
	v := &Vulnerability{
		Provider: "nuclei",
	}

	// Extract info block
	info, ok := raw["info"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("missing info block")
	}

	if name, ok := info["name"].(string); ok {
		v.Name = name
	}
	if severity, ok := info["severity"].(string); ok {
		v.Severity = severity
	}
	if desc, ok := info["description"].(string); ok {
		v.Description = desc
	}
	if tags, ok := info["tags"].([]any); ok {
		for _, t := range tags {
			if s, ok := t.(string); ok {
				v.Tags = append(v.Tags, s)
			}
		}
	}
	if refs, ok := info["reference"].([]any); ok {
		for _, r := range refs {
			if s, ok := r.(string); ok {
				v.References = append(v.References, s)
			}
		}
	}

	// Extract top-level fields
	if matchedAt, ok := raw["matched-at"].(string); ok {
		v.MatchedAt = matchedAt
	}
	if host, ok := raw["host"].(string); ok {
		v.Host = host
	}
	if ip, ok := raw["ip"].(string); ok {
		v.IP = ip
	}
	if templateID, ok := raw["template-id"].(string); ok {
		v.TemplateID = templateID
	}
	if matcherName, ok := raw["matcher-name"].(string); ok {
		v.MatcherName = matcherName
	}

	if v.Name == "" {
		return nil, fmt.Errorf("name field is required")
	}

	return v, nil
}
```

**Step 5: Run test to verify it passes**

Run: `cd /home/jahmyst/Workspace/secator/go && go test ./pkg/types/... -v`
Expected: PASS

**Step 6: Commit**

```bash
git add go/
git commit -m "feat(go): add Vulnerability output type with nuclei parsing"
```

---

## Task 5: Output Types - Additional Types

**Files:**
- Create: `go/pkg/types/subdomain.go`
- Create: `go/pkg/types/certificate.go`
- Create: `go/pkg/types/error.go`
- Create: `go/pkg/types/info.go`

**Step 1: Write Subdomain type**

```go
// go/pkg/types/subdomain.go
package types

// Subdomain represents a discovered subdomain
type Subdomain struct {
	BaseType
	Host       string   `json:"host"`
	Domain     string   `json:"domain,omitempty"`
	Sources    []string `json:"sources,omitempty"`
	Resolved   bool     `json:"resolved,omitempty"`
	IPAddresses []string `json:"ip_addresses,omitempty"`
}

func (s *Subdomain) Type() string {
	return "subdomain"
}

func (s *Subdomain) ToMap() map[string]any {
	m := s.BaseType.ToMap()
	m["_type"] = "subdomain"
	m["host"] = s.Host
	m["domain"] = s.Domain
	m["sources"] = s.Sources
	m["resolved"] = s.Resolved
	m["ip_addresses"] = s.IPAddresses
	return m
}
```

**Step 2: Write Certificate type**

```go
// go/pkg/types/certificate.go
package types

import "time"

// Certificate represents a TLS certificate
type Certificate struct {
	BaseType
	Host      string    `json:"host"`
	Issuer    string    `json:"issuer"`
	Subject   string    `json:"subject"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	SANs      []string  `json:"sans,omitempty"`
}

func (c *Certificate) Type() string {
	return "certificate"
}

func (c *Certificate) ToMap() map[string]any {
	m := c.BaseType.ToMap()
	m["_type"] = "certificate"
	m["host"] = c.Host
	m["issuer"] = c.Issuer
	m["subject"] = c.Subject
	m["not_before"] = c.NotBefore
	m["not_after"] = c.NotAfter
	m["sans"] = c.SANs
	return m
}
```

**Step 3: Write Error and Info types**

```go
// go/pkg/types/error.go
package types

// Error represents an error during execution
type Error struct {
	BaseType
	Message string `json:"message"`
}

func (e *Error) Type() string {
	return "error"
}

func (e *Error) ToMap() map[string]any {
	m := e.BaseType.ToMap()
	m["_type"] = "error"
	m["message"] = e.Message
	return m
}

// NewError creates a new Error
func NewError(msg string) *Error {
	return &Error{Message: msg}
}
```

```go
// go/pkg/types/info.go
package types

// Info represents an informational message
type Info struct {
	BaseType
	Message string `json:"message"`
}

func (i *Info) Type() string {
	return "info"
}

func (i *Info) ToMap() map[string]any {
	m := i.BaseType.ToMap()
	m["_type"] = "info"
	m["message"] = i.Message
	return m
}

// NewInfo creates a new Info message
func NewInfo(msg string) *Info {
	return &Info{Message: msg}
}
```

**Step 4: Run tests**

Run: `cd /home/jahmyst/Workspace/secator/go && go test ./pkg/types/... -v`
Expected: PASS

**Step 5: Commit**

```bash
git add go/
git commit -m "feat(go): add Subdomain, Certificate, Error, Info types"
```

---

## Task 6: Engine - Runner Interface

**Files:**
- Create: `go/internal/engine/runner.go`
- Create: `go/internal/engine/runner_test.go`

**Step 1: Write the failing test**

```go
// go/internal/engine/runner_test.go
package engine

import (
	"context"
	"testing"

	"github.com/freelabz/secator/pkg/types"
	"github.com/stretchr/testify/assert"
)

type mockRunner struct {
	name    string
	results []types.OutputType
}

func (m *mockRunner) Name() string { return m.name }
func (m *mockRunner) Status() Status { return StatusSuccess }
func (m *mockRunner) Run(ctx context.Context, inputs []string) <-chan types.OutputType {
	out := make(chan types.OutputType)
	go func() {
		defer close(out)
		for _, r := range m.results {
			out <- r
		}
	}()
	return out
}

func TestRunner_Interface(t *testing.T) {
	var _ Runner = &mockRunner{}
}

func TestStatus_String(t *testing.T) {
	assert.Equal(t, "pending", StatusPending.String())
	assert.Equal(t, "running", StatusRunning.String())
	assert.Equal(t, "success", StatusSuccess.String())
	assert.Equal(t, "failure", StatusFailure.String())
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/jahmyst/Workspace/secator/go && go test ./internal/engine/... -v`
Expected: FAIL - package not found

**Step 3: Write minimal implementation**

```go
// go/internal/engine/runner.go
package engine

import (
	"context"

	"github.com/freelabz/secator/pkg/types"
)

// Status represents the execution status of a runner
type Status int

const (
	StatusPending Status = iota
	StatusRunning
	StatusSuccess
	StatusFailure
	StatusRevoked
)

func (s Status) String() string {
	switch s {
	case StatusPending:
		return "pending"
	case StatusRunning:
		return "running"
	case StatusSuccess:
		return "success"
	case StatusFailure:
		return "failure"
	case StatusRevoked:
		return "revoked"
	default:
		return "unknown"
	}
}

// Runner executes tasks and emits OutputTypes
type Runner interface {
	Name() string
	Run(ctx context.Context, inputs []string) <-chan types.OutputType
	Status() Status
}

// RunnerState holds the serializable state of a runner
type RunnerState struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Type      string         `json:"type"` // task, workflow, scan
	Status    string         `json:"status"`
	Targets   []string       `json:"targets"`
	StartTime int64          `json:"start_time"`
	EndTime   int64          `json:"end_time,omitempty"`
	Elapsed   float64        `json:"elapsed"`
	Config    map[string]any `json:"config"`
	Errors    []string       `json:"errors"`
	Warnings  []string       `json:"warnings"`
}
```

**Step 4: Run test to verify it passes**

Run: `cd /home/jahmyst/Workspace/secator/go && go test ./internal/engine/... -v`
Expected: PASS

**Step 5: Commit**

```bash
git add go/
git commit -m "feat(go): add Runner interface and Status type"
```

---

## Task 7: Engine - Task Interface

**Files:**
- Modify: `go/internal/engine/runner.go`
- Create: `go/internal/engine/task.go`
- Create: `go/internal/engine/task_test.go`

**Step 1: Write the failing test**

```go
// go/internal/engine/task_test.go
package engine

import (
	"context"
	"testing"

	"github.com/freelabz/secator/pkg/types"
	"github.com/stretchr/testify/assert"
)

type mockTask struct {
	mockRunner
	cmd string
}

func (m *mockTask) Command() string     { return m.cmd }
func (m *mockTask) InputType() string   { return "url" }
func (m *mockTask) OutputTypes() []string { return []string{"url"} }
func (m *mockTask) Install() error      { return nil }
func (m *mockTask) Parse(line []byte) ([]types.OutputType, error) { return nil, nil }
func (m *mockTask) SetOptions(opts map[string]any) {}

func TestTask_Interface(t *testing.T) {
	var _ Task = &mockTask{}
}

func TestTask_Command(t *testing.T) {
	task := &mockTask{cmd: "httpx"}
	assert.Equal(t, "httpx", task.Command())
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/jahmyst/Workspace/secator/go && go test ./internal/engine/... -v`
Expected: FAIL - Task interface not defined

**Step 3: Write minimal implementation**

```go
// go/internal/engine/task.go
package engine

import (
	"github.com/freelabz/secator/pkg/types"
)

// Task wraps an external CLI tool
type Task interface {
	Runner
	Command() string                           // e.g., "httpx"
	InputType() string                         // "url", "host", "ip"
	OutputTypes() []string                     // ["url", "subdomain"]
	Install() error                            // Auto-installation
	Parse(line []byte) ([]types.OutputType, error)   // Parse single output line
	SetOptions(opts map[string]any)            // Configure task options
}
```

**Step 4: Run test to verify it passes**

Run: `cd /home/jahmyst/Workspace/secator/go && go test ./internal/engine/... -v`
Expected: PASS

**Step 5: Commit**

```bash
git add go/
git commit -m "feat(go): add Task interface"
```

---

## Task 8: Engine - Executor (Command Wrapper)

**Files:**
- Create: `go/internal/engine/executor.go`
- Create: `go/internal/engine/executor_test.go`

**Step 1: Write the failing test**

```go
// go/internal/engine/executor_test.go
package engine

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExecutor_RunSimpleCommand(t *testing.T) {
	exec := NewExecutor("echo", []string{"hello"})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	lines, err := exec.Run(ctx)
	require.NoError(t, err)

	var output []string
	for line := range lines {
		output = append(output, line)
	}

	require.Len(t, output, 1)
	assert.Equal(t, "hello", output[0])
}

func TestExecutor_ContextCancellation(t *testing.T) {
	exec := NewExecutor("sleep", []string{"10"})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	lines, err := exec.Run(ctx)
	require.NoError(t, err)

	// Drain channel
	for range lines {
	}

	// Context should be cancelled
	assert.Error(t, ctx.Err())
}

func TestExecutor_WithStdin(t *testing.T) {
	exec := NewExecutor("cat", []string{})
	exec.SetStdin([]string{"line1", "line2"})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	lines, err := exec.Run(ctx)
	require.NoError(t, err)

	var output []string
	for line := range lines {
		output = append(output, line)
	}

	assert.Equal(t, []string{"line1", "line2"}, output)
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/jahmyst/Workspace/secator/go && go test ./internal/engine/... -v`
Expected: FAIL - Executor not defined

**Step 3: Write minimal implementation**

```go
// go/internal/engine/executor.go
package engine

import (
	"bufio"
	"context"
	"io"
	"os/exec"
	"strings"
)

// Executor runs external commands with streaming output
type Executor struct {
	command string
	args    []string
	stdin   []string
	env     []string
}

// NewExecutor creates a new executor for a command
func NewExecutor(command string, args []string) *Executor {
	return &Executor{
		command: command,
		args:    args,
	}
}

// SetStdin sets lines to write to stdin
func (e *Executor) SetStdin(lines []string) {
	e.stdin = lines
}

// SetEnv sets environment variables
func (e *Executor) SetEnv(env []string) {
	e.env = env
}

// Run executes the command and streams stdout lines
func (e *Executor) Run(ctx context.Context) (<-chan string, error) {
	cmd := exec.CommandContext(ctx, e.command, e.args...)

	if len(e.env) > 0 {
		cmd.Env = e.env
	}

	var stdin io.WriteCloser
	var err error
	if len(e.stdin) > 0 {
		stdin, err = cmd.StdinPipe()
		if err != nil {
			return nil, err
		}
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	out := make(chan string, 100)

	go func() {
		defer close(out)

		// Write stdin if provided
		if stdin != nil {
			go func() {
				for _, line := range e.stdin {
					stdin.Write([]byte(line + "\n"))
				}
				stdin.Close()
			}()
		}

		// Read stdout
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				select {
				case out <- line:
				case <-ctx.Done():
					return
				}
			}
		}

		cmd.Wait()
	}()

	return out, nil
}
```

**Step 4: Run test to verify it passes**

Run: `cd /home/jahmyst/Workspace/secator/go && go test ./internal/engine/... -v`
Expected: PASS

**Step 5: Commit**

```bash
git add go/
git commit -m "feat(go): add Executor for running external commands"
```

---

## Task 9: Task Registry

**Files:**
- Create: `go/internal/tasks/registry.go`
- Create: `go/internal/tasks/registry_test.go`

**Step 1: Write the failing test**

```go
// go/internal/tasks/registry_test.go
package tasks

import (
	"testing"

	"github.com/freelabz/secator/internal/engine"
	"github.com/stretchr/testify/assert"
)

func TestRegistry_RegisterAndGet(t *testing.T) {
	// Clear registry for test
	registry = make(map[string]TaskFactory)

	factory := func() engine.Task { return nil }
	Register("test-task", factory)

	got, ok := Get("test-task")
	assert.True(t, ok)
	assert.NotNil(t, got)
}

func TestRegistry_GetUnknown(t *testing.T) {
	registry = make(map[string]TaskFactory)

	_, ok := Get("unknown")
	assert.False(t, ok)
}

func TestRegistry_All(t *testing.T) {
	registry = make(map[string]TaskFactory)

	Register("task1", func() engine.Task { return nil })
	Register("task2", func() engine.Task { return nil })

	all := All()
	assert.Len(t, all, 2)
	assert.Contains(t, all, "task1")
	assert.Contains(t, all, "task2")
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/jahmyst/Workspace/secator/go && go test ./internal/tasks/... -v`
Expected: FAIL - package not found

**Step 3: Write minimal implementation**

```go
// go/internal/tasks/registry.go
package tasks

import (
	"github.com/freelabz/secator/internal/engine"
)

// TaskFactory creates a new task instance
type TaskFactory func() engine.Task

var registry = make(map[string]TaskFactory)

// Register adds a task factory to the registry
func Register(name string, factory TaskFactory) {
	registry[name] = factory
}

// Get retrieves a task by name
func Get(name string) (engine.Task, bool) {
	factory, ok := registry[name]
	if !ok {
		return nil, false
	}
	return factory(), true
}

// All returns all registered task names and factories
func All() map[string]TaskFactory {
	result := make(map[string]TaskFactory)
	for k, v := range registry {
		result[k] = v
	}
	return result
}

// Names returns all registered task names
func Names() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	return names
}
```

**Step 4: Run test to verify it passes**

Run: `cd /home/jahmyst/Workspace/secator/go && go test ./internal/tasks/... -v`
Expected: PASS

**Step 5: Commit**

```bash
git add go/
git commit -m "feat(go): add task registry"
```

---

## Task 10: httpx Task Implementation

**Files:**
- Create: `go/internal/tasks/httpx/httpx.go`
- Create: `go/internal/tasks/httpx/httpx_test.go`

**Step 1: Write the failing test**

```go
// go/internal/tasks/httpx/httpx_test.go
package httpx

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/freelabz/secator/internal/engine"
	"github.com/freelabz/secator/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHttpx_ImplementsTask(t *testing.T) {
	var _ engine.Task = &Httpx{}
}

func TestHttpx_Command(t *testing.T) {
	h := New()
	assert.Equal(t, "httpx", h.Command())
}

func TestHttpx_InputType(t *testing.T) {
	h := New()
	assert.Equal(t, "url", h.InputType())
}

func TestHttpx_OutputTypes(t *testing.T) {
	h := New()
	outputs := h.OutputTypes()
	assert.Contains(t, outputs, "url")
	assert.Contains(t, outputs, "subdomain")
	assert.Contains(t, outputs, "certificate")
}

func TestHttpx_Parse(t *testing.T) {
	h := New()

	data, err := os.ReadFile("../../../testdata/httpx_output.json")
	require.NoError(t, err)

	results, err := h.Parse(data)
	require.NoError(t, err)
	require.NotEmpty(t, results)

	// First result should be URL
	url, ok := results[0].(*types.URL)
	require.True(t, ok)
	assert.Equal(t, "https://media.example.synology.me:443", url.URL)
	assert.Equal(t, 200, url.StatusCode)
	assert.Contains(t, url.Technologies, "Nginx")
}

func TestHttpx_BuildArgs(t *testing.T) {
	h := New()
	h.SetOptions(map[string]any{
		"tech_detect": true,
		"threads":     50,
	})

	args := h.BuildArgs()
	assert.Contains(t, args, "-json")
	assert.Contains(t, args, "-silent")
	assert.Contains(t, args, "-tech-detect")
	assert.Contains(t, args, "-threads")
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/jahmyst/Workspace/secator/go && go test ./internal/tasks/httpx/... -v`
Expected: FAIL - package not found

**Step 3: Write implementation**

```go
// go/internal/tasks/httpx/httpx.go
package httpx

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/freelabz/secator/internal/engine"
	"github.com/freelabz/secator/internal/tasks"
	"github.com/freelabz/secator/pkg/types"
)

func init() {
	tasks.Register("httpx", func() engine.Task { return New() })
}

// Options for httpx
type Options struct {
	TechDetect    bool     `json:"tech_detect"`
	TLSGrab       bool     `json:"tls_grab"`
	StatusCode    bool     `json:"status_code"`
	Threads       int      `json:"threads"`
	RateLimit     int      `json:"rate_limit"`
	Timeout       int      `json:"timeout"`
	FollowRedirects bool   `json:"follow_redirects"`
	Headers       []string `json:"headers"`
}

// Httpx task wraps the httpx tool
type Httpx struct {
	opts   Options
	status engine.Status
}

// New creates a new httpx task
func New() *Httpx {
	return &Httpx{
		opts: Options{
			Threads: 50,
			Timeout: 10,
		},
		status: engine.StatusPending,
	}
}

func (h *Httpx) Name() string      { return "httpx" }
func (h *Httpx) Command() string   { return "httpx" }
func (h *Httpx) InputType() string { return "url" }
func (h *Httpx) Status() engine.Status { return h.status }

func (h *Httpx) OutputTypes() []string {
	return []string{"url", "subdomain", "certificate"}
}

func (h *Httpx) Install() error {
	// go install github.com/projectdiscovery/httpx/cmd/httpx@latest
	return nil
}

func (h *Httpx) SetOptions(opts map[string]any) {
	if v, ok := opts["tech_detect"].(bool); ok {
		h.opts.TechDetect = v
	}
	if v, ok := opts["tls_grab"].(bool); ok {
		h.opts.TLSGrab = v
	}
	if v, ok := opts["threads"].(int); ok {
		h.opts.Threads = v
	}
	if v, ok := opts["rate_limit"].(int); ok {
		h.opts.RateLimit = v
	}
	if v, ok := opts["timeout"].(int); ok {
		h.opts.Timeout = v
	}
	if v, ok := opts["follow_redirects"].(bool); ok {
		h.opts.FollowRedirects = v
	}
}

// BuildArgs constructs CLI arguments
func (h *Httpx) BuildArgs() []string {
	args := []string{"-json", "-silent"}

	if h.opts.TechDetect {
		args = append(args, "-tech-detect")
	}
	if h.opts.TLSGrab {
		args = append(args, "-tls-grab")
	}
	if h.opts.Threads > 0 {
		args = append(args, "-threads", strconv.Itoa(h.opts.Threads))
	}
	if h.opts.RateLimit > 0 {
		args = append(args, "-rate-limit", strconv.Itoa(h.opts.RateLimit))
	}
	if h.opts.Timeout > 0 {
		args = append(args, "-timeout", strconv.Itoa(h.opts.Timeout))
	}
	if h.opts.FollowRedirects {
		args = append(args, "-follow-redirects")
	}
	for _, header := range h.opts.Headers {
		args = append(args, "-H", header)
	}

	return args
}

// Parse converts a JSON line to OutputTypes
func (h *Httpx) Parse(line []byte) ([]types.OutputType, error) {
	var raw map[string]any
	if err := json.Unmarshal(line, &raw); err != nil {
		return nil, err
	}

	var results []types.OutputType

	// Primary: URL output
	url, err := types.URLFromMap(raw)
	if err != nil {
		return nil, err
	}
	url.SetSource("httpx")
	results = append(results, url)

	// TODO: Extract TLS certificate and subdomains from SANs

	return results, nil
}

// Run executes httpx and streams results
func (h *Httpx) Run(ctx context.Context, inputs []string) <-chan types.OutputType {
	out := make(chan types.OutputType, 100)

	go func() {
		defer close(out)
		h.status = engine.StatusRunning

		args := h.BuildArgs()
		exec := engine.NewExecutor(h.Command(), args)
		exec.SetStdin(inputs)

		lines, err := exec.Run(ctx)
		if err != nil {
			out <- types.NewError(err.Error())
			h.status = engine.StatusFailure
			return
		}

		for line := range lines {
			results, err := h.Parse([]byte(line))
			if err != nil {
				out <- types.NewError(err.Error())
				continue
			}
			for _, r := range results {
				select {
				case out <- r:
				case <-ctx.Done():
					h.status = engine.StatusRevoked
					return
				}
			}
		}

		h.status = engine.StatusSuccess
	}()

	return out
}
```

**Step 4: Run test to verify it passes**

Run: `cd /home/jahmyst/Workspace/secator/go && go test ./internal/tasks/httpx/... -v`
Expected: PASS

**Step 5: Commit**

```bash
git add go/
git commit -m "feat(go): add httpx task implementation"
```

---

## Task 11: nuclei Task Implementation

**Files:**
- Create: `go/internal/tasks/nuclei/nuclei.go`
- Create: `go/internal/tasks/nuclei/nuclei_test.go`

**Step 1: Write the failing test**

```go
// go/internal/tasks/nuclei/nuclei_test.go
package nuclei

import (
	"os"
	"testing"

	"github.com/freelabz/secator/internal/engine"
	"github.com/freelabz/secator/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNuclei_ImplementsTask(t *testing.T) {
	var _ engine.Task = &Nuclei{}
}

func TestNuclei_Command(t *testing.T) {
	n := New()
	assert.Equal(t, "nuclei", n.Command())
}

func TestNuclei_Parse(t *testing.T) {
	n := New()

	data, err := os.ReadFile("../../../testdata/nuclei_output.json")
	require.NoError(t, err)

	results, err := n.Parse(data)
	require.NoError(t, err)
	require.Len(t, results, 1)

	vuln, ok := results[0].(*types.Vulnerability)
	require.True(t, ok)
	assert.Equal(t, "HTTP Missing Security Headers", vuln.Name)
	assert.Equal(t, "info", vuln.Severity)
	assert.Equal(t, "nuclei", vuln.Provider)
}

func TestNuclei_BuildArgs(t *testing.T) {
	n := New()
	n.SetOptions(map[string]any{
		"severity":   []string{"critical", "high"},
		"rate_limit": 100,
	})

	args := n.BuildArgs()
	assert.Contains(t, args, "-jsonl")
	assert.Contains(t, args, "-silent")
	assert.Contains(t, args, "-severity")
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/jahmyst/Workspace/secator/go && go test ./internal/tasks/nuclei/... -v`
Expected: FAIL - package not found

**Step 3: Write implementation**

```go
// go/internal/tasks/nuclei/nuclei.go
package nuclei

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/freelabz/secator/internal/engine"
	"github.com/freelabz/secator/internal/tasks"
	"github.com/freelabz/secator/pkg/types"
)

func init() {
	tasks.Register("nuclei", func() engine.Task { return New() })
}

// Options for nuclei
type Options struct {
	Templates    []string `json:"templates"`
	Severity     []string `json:"severity"` // critical, high, medium, low, info
	Tags         []string `json:"tags"`
	ExcludeTags  []string `json:"exclude_tags"`
	RateLimit    int      `json:"rate_limit"`
	Concurrency  int      `json:"concurrency"`
	Timeout      int      `json:"timeout"`
}

// Nuclei task wraps the nuclei tool
type Nuclei struct {
	opts   Options
	status engine.Status
}

// New creates a new nuclei task
func New() *Nuclei {
	return &Nuclei{
		opts: Options{
			Concurrency: 25,
			RateLimit:   150,
			Timeout:     10,
		},
		status: engine.StatusPending,
	}
}

func (n *Nuclei) Name() string      { return "nuclei" }
func (n *Nuclei) Command() string   { return "nuclei" }
func (n *Nuclei) InputType() string { return "url" }
func (n *Nuclei) Status() engine.Status { return n.status }

func (n *Nuclei) OutputTypes() []string {
	return []string{"vulnerability"}
}

func (n *Nuclei) Install() error {
	// go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
	return nil
}

func (n *Nuclei) SetOptions(opts map[string]any) {
	if v, ok := opts["templates"].([]string); ok {
		n.opts.Templates = v
	}
	if v, ok := opts["severity"].([]string); ok {
		n.opts.Severity = v
	}
	if v, ok := opts["tags"].([]string); ok {
		n.opts.Tags = v
	}
	if v, ok := opts["exclude_tags"].([]string); ok {
		n.opts.ExcludeTags = v
	}
	if v, ok := opts["rate_limit"].(int); ok {
		n.opts.RateLimit = v
	}
	if v, ok := opts["concurrency"].(int); ok {
		n.opts.Concurrency = v
	}
}

// BuildArgs constructs CLI arguments
func (n *Nuclei) BuildArgs() []string {
	args := []string{"-jsonl", "-silent"}

	if len(n.opts.Templates) > 0 {
		args = append(args, "-t", strings.Join(n.opts.Templates, ","))
	}
	if len(n.opts.Severity) > 0 {
		args = append(args, "-severity", strings.Join(n.opts.Severity, ","))
	}
	if len(n.opts.Tags) > 0 {
		args = append(args, "-tags", strings.Join(n.opts.Tags, ","))
	}
	if len(n.opts.ExcludeTags) > 0 {
		args = append(args, "-exclude-tags", strings.Join(n.opts.ExcludeTags, ","))
	}
	if n.opts.RateLimit > 0 {
		args = append(args, "-rate-limit", strconv.Itoa(n.opts.RateLimit))
	}
	if n.opts.Concurrency > 0 {
		args = append(args, "-concurrency", strconv.Itoa(n.opts.Concurrency))
	}

	return args
}

// Parse converts a JSON line to OutputTypes
func (n *Nuclei) Parse(line []byte) ([]types.OutputType, error) {
	var raw map[string]any
	if err := json.Unmarshal(line, &raw); err != nil {
		return nil, err
	}

	vuln, err := types.VulnerabilityFromMap(raw)
	if err != nil {
		return nil, err
	}
	vuln.SetSource("nuclei")

	return []types.OutputType{vuln}, nil
}

// Run executes nuclei and streams results
func (n *Nuclei) Run(ctx context.Context, inputs []string) <-chan types.OutputType {
	out := make(chan types.OutputType, 100)

	go func() {
		defer close(out)
		n.status = engine.StatusRunning

		args := n.BuildArgs()
		exec := engine.NewExecutor(n.Command(), args)
		exec.SetStdin(inputs)

		lines, err := exec.Run(ctx)
		if err != nil {
			out <- types.NewError(err.Error())
			n.status = engine.StatusFailure
			return
		}

		for line := range lines {
			results, err := n.Parse([]byte(line))
			if err != nil {
				// Non-JSON lines are common (progress, etc.) - skip silently
				continue
			}
			for _, r := range results {
				select {
				case out <- r:
				case <-ctx.Done():
					n.status = engine.StatusRevoked
					return
				}
			}
		}

		n.status = engine.StatusSuccess
	}()

	return out
}
```

**Step 4: Run test to verify it passes**

Run: `cd /home/jahmyst/Workspace/secator/go && go test ./internal/tasks/nuclei/... -v`
Expected: PASS

**Step 5: Commit**

```bash
git add go/
git commit -m "feat(go): add nuclei task implementation"
```

---

## Task 12: Store Interface

**Files:**
- Create: `go/internal/store/store.go`
- Create: `go/internal/store/store_test.go`

**Step 1: Write the interface and mock**

```go
// go/internal/store/store.go
package store

import (
	"context"

	"github.com/freelabz/secator/internal/engine"
	"github.com/freelabz/secator/pkg/types"
)

// Duplicate represents a set of duplicate findings
type Duplicate struct {
	MainID     string
	RelatedIDs []string
}

// Store persists findings and runner state
type Store interface {
	Name() string
	SaveRunner(ctx context.Context, r *engine.RunnerState) error
	UpdateRunner(ctx context.Context, id string, r *engine.RunnerState) error
	SaveFinding(ctx context.Context, f types.OutputType) error
	UpdateFinding(ctx context.Context, id string, f types.OutputType) error
	FindDuplicates(ctx context.Context, workspace string) ([]Duplicate, error)
	Close() error
}

// MultiStore wraps multiple stores
type MultiStore struct {
	stores []Store
}

// NewMultiStore creates a store that writes to multiple backends
func NewMultiStore(stores ...Store) *MultiStore {
	return &MultiStore{stores: stores}
}

func (m *MultiStore) Name() string { return "multi" }

func (m *MultiStore) SaveRunner(ctx context.Context, r *engine.RunnerState) error {
	for _, s := range m.stores {
		if err := s.SaveRunner(ctx, r); err != nil {
			return err
		}
	}
	return nil
}

func (m *MultiStore) UpdateRunner(ctx context.Context, id string, r *engine.RunnerState) error {
	for _, s := range m.stores {
		if err := s.UpdateRunner(ctx, id, r); err != nil {
			return err
		}
	}
	return nil
}

func (m *MultiStore) SaveFinding(ctx context.Context, f types.OutputType) error {
	for _, s := range m.stores {
		if err := s.SaveFinding(ctx, f); err != nil {
			return err
		}
	}
	return nil
}

func (m *MultiStore) UpdateFinding(ctx context.Context, id string, f types.OutputType) error {
	for _, s := range m.stores {
		if err := s.UpdateFinding(ctx, id, f); err != nil {
			return err
		}
	}
	return nil
}

func (m *MultiStore) FindDuplicates(ctx context.Context, workspace string) ([]Duplicate, error) {
	// Use first store that supports duplicates
	for _, s := range m.stores {
		dups, err := s.FindDuplicates(ctx, workspace)
		if err == nil && len(dups) > 0 {
			return dups, nil
		}
	}
	return nil, nil
}

func (m *MultiStore) Close() error {
	for _, s := range m.stores {
		s.Close()
	}
	return nil
}
```

**Step 2: Write test**

```go
// go/internal/store/store_test.go
package store

import (
	"context"
	"testing"

	"github.com/freelabz/secator/internal/engine"
	"github.com/freelabz/secator/pkg/types"
	"github.com/stretchr/testify/assert"
)

type mockStore struct {
	name     string
	findings []types.OutputType
	runners  []*engine.RunnerState
}

func (m *mockStore) Name() string { return m.name }
func (m *mockStore) SaveRunner(ctx context.Context, r *engine.RunnerState) error {
	m.runners = append(m.runners, r)
	return nil
}
func (m *mockStore) UpdateRunner(ctx context.Context, id string, r *engine.RunnerState) error {
	return nil
}
func (m *mockStore) SaveFinding(ctx context.Context, f types.OutputType) error {
	m.findings = append(m.findings, f)
	return nil
}
func (m *mockStore) UpdateFinding(ctx context.Context, id string, f types.OutputType) error {
	return nil
}
func (m *mockStore) FindDuplicates(ctx context.Context, workspace string) ([]Duplicate, error) {
	return nil, nil
}
func (m *mockStore) Close() error { return nil }

func TestMultiStore_SaveFinding(t *testing.T) {
	s1 := &mockStore{name: "s1"}
	s2 := &mockStore{name: "s2"}
	multi := NewMultiStore(s1, s2)

	url := &types.URL{URL: "https://example.com"}
	err := multi.SaveFinding(context.Background(), url)

	assert.NoError(t, err)
	assert.Len(t, s1.findings, 1)
	assert.Len(t, s2.findings, 1)
}
```

**Step 3: Run test**

Run: `cd /home/jahmyst/Workspace/secator/go && go test ./internal/store/... -v`
Expected: PASS

**Step 4: Commit**

```bash
git add go/
git commit -m "feat(go): add Store interface and MultiStore"
```

---

## Task 13: MongoDB Store

**Files:**
- Create: `go/internal/store/mongodb/mongodb.go`
- Create: `go/internal/store/mongodb/mongodb_test.go`

**Step 1: Write the implementation**

```go
// go/internal/store/mongodb/mongodb.go
package mongodb

import (
	"context"
	"time"

	"github.com/freelabz/secator/internal/engine"
	"github.com/freelabz/secator/internal/store"
	"github.com/freelabz/secator/pkg/types"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Config for MongoDB connection
type Config struct {
	URL                    string `yaml:"url"`
	Database               string `yaml:"database"`
	ServerSelectionTimeout int    `yaml:"server_selection_timeout_ms"`
	MaxPoolSize            int    `yaml:"max_pool_size"`
}

// Store implements store.Store for MongoDB
type Store struct {
	client    *mongo.Client
	db        *mongo.Database
	tasks     *mongo.Collection
	workflows *mongo.Collection
	scans     *mongo.Collection
	findings  *mongo.Collection
}

// New creates a new MongoDB store
func New(cfg Config) (*Store, error) {
	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(cfg.ServerSelectionTimeout)*time.Millisecond)
	defer cancel()

	opts := options.Client().
		ApplyURI(cfg.URL).
		SetMaxPoolSize(uint64(cfg.MaxPoolSize))

	client, err := mongo.Connect(ctx, opts)
	if err != nil {
		return nil, err
	}

	// Ping to verify connection
	if err := client.Ping(ctx, nil); err != nil {
		return nil, err
	}

	db := client.Database(cfg.Database)
	return &Store{
		client:    client,
		db:        db,
		tasks:     db.Collection("tasks"),
		workflows: db.Collection("workflows"),
		scans:     db.Collection("scans"),
		findings:  db.Collection("findings"),
	}, nil
}

func (s *Store) Name() string { return "mongodb" }

func (s *Store) SaveFinding(ctx context.Context, f types.OutputType) error {
	doc := f.ToMap()
	doc["_id"] = f.UUID()

	_, err := s.findings.InsertOne(ctx, doc)
	if mongo.IsDuplicateKeyError(err) {
		_, err = s.findings.ReplaceOne(ctx, bson.M{"_id": f.UUID()}, doc)
	}
	return err
}

func (s *Store) UpdateFinding(ctx context.Context, id string, f types.OutputType) error {
	doc := f.ToMap()
	_, err := s.findings.ReplaceOne(ctx, bson.M{"_id": id}, doc)
	return err
}

func (s *Store) SaveRunner(ctx context.Context, r *engine.RunnerState) error {
	coll := s.collectionForType(r.Type)
	_, err := coll.InsertOne(ctx, r)
	return err
}

func (s *Store) UpdateRunner(ctx context.Context, id string, r *engine.RunnerState) error {
	coll := s.collectionForType(r.Type)
	_, err := coll.ReplaceOne(ctx, bson.M{"_id": id}, r)
	return err
}

func (s *Store) collectionForType(runnerType string) *mongo.Collection {
	switch runnerType {
	case "workflow":
		return s.workflows
	case "scan":
		return s.scans
	default:
		return s.tasks
	}
}

func (s *Store) FindDuplicates(ctx context.Context, workspace string) ([]store.Duplicate, error) {
	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.M{"_context.workspace": workspace}}},
		{{Key: "$group", Value: bson.M{
			"_id":   "$_hash",
			"ids":   bson.M{"$push": "$_id"},
			"count": bson.M{"$sum": 1},
		}}},
		{{Key: "$match", Value: bson.M{"count": bson.M{"$gt": 1}}}},
	}

	cursor, err := s.findings.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var results []store.Duplicate
	for cursor.Next(ctx) {
		var doc struct {
			IDs []string `bson:"ids"`
		}
		if err := cursor.Decode(&doc); err != nil {
			continue
		}
		if len(doc.IDs) > 1 {
			results = append(results, store.Duplicate{
				MainID:     doc.IDs[0],
				RelatedIDs: doc.IDs[1:],
			})
		}
	}

	return results, nil
}

func (s *Store) Close() error {
	return s.client.Disconnect(context.Background())
}
```

**Step 2: Write test (unit test with mock, integration test requires MongoDB)**

```go
// go/internal/store/mongodb/mongodb_test.go
package mongodb

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfig_Defaults(t *testing.T) {
	cfg := Config{
		URL:                    "mongodb://localhost:27017",
		Database:               "secator",
		ServerSelectionTimeout: 5000,
		MaxPoolSize:            10,
	}

	assert.Equal(t, "mongodb://localhost:27017", cfg.URL)
	assert.Equal(t, "secator", cfg.Database)
}

// Integration test - requires MongoDB
// func TestStore_Integration(t *testing.T) {
//     if testing.Short() {
//         t.Skip("skipping integration test")
//     }
//     // ...
// }
```

**Step 3: Run test**

Run: `cd /home/jahmyst/Workspace/secator/go && go mod tidy && go test ./internal/store/mongodb/... -v`
Expected: PASS

**Step 4: Commit**

```bash
git add go/
git commit -m "feat(go): add MongoDB store implementation"
```

---

## Task 14: GCS Store

**Files:**
- Create: `go/internal/store/gcs/gcs.go`

**Step 1: Write implementation**

```go
// go/internal/store/gcs/gcs.go
package gcs

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"cloud.google.com/go/storage"
	"github.com/freelabz/secator/internal/engine"
	"github.com/freelabz/secator/internal/store"
	"github.com/freelabz/secator/pkg/types"
)

// Config for GCS
type Config struct {
	BucketName string `yaml:"bucket_name"`
}

// Store implements store.Store for GCS (file uploads only)
type Store struct {
	client *storage.Client
	bucket *storage.BucketHandle
	config Config
}

// New creates a new GCS store
func New(cfg Config) (*Store, error) {
	ctx := context.Background()
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, err
	}

	return &Store{
		client: client,
		bucket: client.Bucket(cfg.BucketName),
		config: cfg,
	}, nil
}

func (s *Store) Name() string { return "gcs" }

// SaveFinding uploads associated files (screenshots, responses)
func (s *Store) SaveFinding(ctx context.Context, f types.OutputType) error {
	m := f.ToMap()

	// Check for file paths to upload
	fileFields := []string{"screenshot_path", "stored_response_path"}

	for _, field := range fileFields {
		if path, ok := m[field].(string); ok && path != "" {
			if _, err := os.Stat(path); err == nil {
				gcsPath, err := s.upload(ctx, path)
				if err != nil {
					return err
				}
				// Note: caller should handle updating the finding with GCS path
				_ = gcsPath
			}
		}
	}

	return nil
}

func (s *Store) upload(ctx context.Context, localPath string) (string, error) {
	filename := filepath.Base(localPath)
	blobName := fmt.Sprintf("findings/%s/%s", time.Now().Format("2006-01-02"), filename)

	obj := s.bucket.Object(blobName)
	w := obj.NewWriter(ctx)

	f, err := os.Open(localPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	if _, err := io.Copy(w, f); err != nil {
		return "", err
	}

	if err := w.Close(); err != nil {
		return "", err
	}

	return fmt.Sprintf("gs://%s/%s", s.config.BucketName, blobName), nil
}

// Runner methods are no-ops for GCS (it's just for file storage)
func (s *Store) SaveRunner(ctx context.Context, r *engine.RunnerState) error   { return nil }
func (s *Store) UpdateRunner(ctx context.Context, id string, r *engine.RunnerState) error { return nil }
func (s *Store) UpdateFinding(ctx context.Context, id string, f types.OutputType) error   { return nil }
func (s *Store) FindDuplicates(ctx context.Context, workspace string) ([]store.Duplicate, error) {
	return nil, nil
}
func (s *Store) Close() error { return s.client.Close() }
```

**Step 2: Commit**

```bash
git add go/
git commit -m "feat(go): add GCS store implementation"
```

---

## Task 15: API Store

**Files:**
- Create: `go/internal/store/api/api.go`

**Step 1: Write implementation**

```go
// go/internal/store/api/api.go
package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/freelabz/secator/internal/engine"
	"github.com/freelabz/secator/internal/store"
	"github.com/freelabz/secator/pkg/types"
)

// Endpoints configuration
type Endpoints struct {
	RunnerCreate  string `yaml:"runner_create"`
	RunnerUpdate  string `yaml:"runner_update"`
	FindingCreate string `yaml:"finding_create"`
	FindingUpdate string `yaml:"finding_update"`
}

// Config for API store
type Config struct {
	URL        string    `yaml:"url"`
	Key        string    `yaml:"key"`
	HeaderName string    `yaml:"header_name"`
	ForceSSL   bool      `yaml:"force_ssl"`
	Endpoints  Endpoints `yaml:"endpoints"`
}

// Store implements store.Store for HTTP API
type Store struct {
	baseURL    string
	apiKey     string
	headerName string
	client     *http.Client
	endpoints  Endpoints
}

// New creates a new API store
func New(cfg Config) (*Store, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !cfg.ForceSSL},
	}

	return &Store{
		baseURL:    cfg.URL,
		apiKey:     cfg.Key,
		headerName: cfg.HeaderName,
		client:     &http.Client{Transport: transport, Timeout: 30 * time.Second},
		endpoints:  cfg.Endpoints,
	}, nil
}

func (s *Store) Name() string { return "api" }

func (s *Store) SaveFinding(ctx context.Context, f types.OutputType) error {
	url := s.baseURL + s.endpoints.FindingCreate
	return s.post(ctx, url, f.ToMap())
}

func (s *Store) UpdateFinding(ctx context.Context, id string, f types.OutputType) error {
	url := s.baseURL + strings.Replace(s.endpoints.FindingUpdate, "{finding_id}", id, 1)
	return s.put(ctx, url, f.ToMap())
}

func (s *Store) SaveRunner(ctx context.Context, r *engine.RunnerState) error {
	url := s.baseURL + s.endpoints.RunnerCreate
	return s.post(ctx, url, r)
}

func (s *Store) UpdateRunner(ctx context.Context, id string, r *engine.RunnerState) error {
	url := s.baseURL + strings.Replace(s.endpoints.RunnerUpdate, "{runner_id}", id, 1)
	return s.put(ctx, url, r)
}

func (s *Store) FindDuplicates(ctx context.Context, workspace string) ([]store.Duplicate, error) {
	return nil, nil
}

func (s *Store) Close() error { return nil }

func (s *Store) post(ctx context.Context, url string, body any) error {
	return s.request(ctx, "POST", url, body)
}

func (s *Store) put(ctx context.Context, url string, body any) error {
	return s.request(ctx, "PUT", url, body)
}

func (s *Store) request(ctx context.Context, method, url string, body any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(data))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	if s.apiKey != "" {
		req.Header.Set(s.headerName, s.apiKey)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error %d: %s", resp.StatusCode, body)
	}

	return nil
}
```

**Step 2: Commit**

```bash
git add go/
git commit -m "feat(go): add API store implementation"
```

---

## Task 16: CLI - Basic Structure

**Files:**
- Modify: `go/cmd/secator/main.go`
- Create: `go/cmd/secator/task.go`
- Create: `go/cmd/secator/workflow.go`
- Create: `go/cmd/secator/worker.go`

**Step 1: Update main.go with Cobra**

```go
// go/cmd/secator/main.go
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "secator",
	Short: "The Pentester's Swiss Knife",
	Long:  "A security assessment automation tool written in Go",
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().StringP("output", "o", "", "Output format (json, csv)")
	rootCmd.PersistentFlags().StringP("profile", "p", "", "Profile (aggressive, stealth)")
	rootCmd.PersistentFlags().Bool("json", false, "JSON output")
	rootCmd.PersistentFlags().StringSlice("store", nil, "Stores to use (mongodb, gcs, api)")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
```

**Step 2: Create task command**

```go
// go/cmd/secator/task.go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"

	"github.com/freelabz/secator/internal/tasks"
	// Import task packages for registration
	_ "github.com/freelabz/secator/internal/tasks/httpx"
	_ "github.com/freelabz/secator/internal/tasks/nuclei"
	"github.com/spf13/cobra"
)

var taskCmd = &cobra.Command{
	Use:     "x [task] [targets...]",
	Aliases: []string{"t", "task"},
	Short:   "Run a task",
	Args:    cobra.MinimumNArgs(2),
	Run:     runTask,
}

func init() {
	rootCmd.AddCommand(taskCmd)
}

func runTask(cmd *cobra.Command, args []string) {
	taskName := args[0]
	targets := args[1:]

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	task, ok := tasks.Get(taskName)
	if !ok {
		fmt.Fprintf(os.Stderr, "Unknown task: %s\n", taskName)
		fmt.Fprintf(os.Stderr, "Available tasks: %v\n", tasks.Names())
		os.Exit(1)
	}

	jsonOutput, _ := cmd.Flags().GetBool("json")

	for result := range task.Run(ctx, targets) {
		if jsonOutput {
			data, _ := json.Marshal(result.ToMap())
			fmt.Println(string(data))
		} else {
			fmt.Printf("[%s] %v\n", result.Type(), result.ToMap())
		}
	}
}
```

**Step 3: Create worker command placeholder**

```go
// go/cmd/secator/worker.go
package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var workerCmd = &cobra.Command{
	Use:   "worker",
	Short: "Start a worker",
	Run:   runWorker,
}

func init() {
	workerCmd.Flags().IntP("concurrency", "c", 0, "Worker concurrency")
	rootCmd.AddCommand(workerCmd)
}

func runWorker(cmd *cobra.Command, args []string) {
	fmt.Println("Worker mode not yet implemented")
}
```

**Step 4: Create health command**

```go
// go/cmd/secator/health.go
package main

import (
	"fmt"
	"os/exec"

	"github.com/freelabz/secator/internal/tasks"
	"github.com/spf13/cobra"
)

var healthCmd = &cobra.Command{
	Use:   "health",
	Short: "Check installed tools",
	Run:   runHealth,
}

func init() {
	rootCmd.AddCommand(healthCmd)
}

func runHealth(cmd *cobra.Command, args []string) {
	fmt.Println("Checking installed tools...")
	fmt.Println()

	for _, name := range tasks.Names() {
		task, _ := tasks.Get(name)
		cmdName := task.Command()

		_, err := exec.LookPath(cmdName)
		if err != nil {
			fmt.Printf("  [✗] %s - not found\n", name)
		} else {
			fmt.Printf("  [✓] %s\n", name)
		}
	}
}
```

**Step 5: Build and test**

Run: `cd /home/jahmyst/Workspace/secator/go && go mod tidy && go build -o bin/secator ./cmd/secator`
Expected: Binary builds successfully

Run: `./bin/secator --help`
Expected: Shows help with x, worker, health commands

Run: `./bin/secator health`
Expected: Shows installed tool status

**Step 6: Commit**

```bash
git add go/
git commit -m "feat(go): add CLI with task, worker, health commands"
```

---

## Task 17: Workflow Loader

**Files:**
- Create: `go/internal/workflow/loader.go`
- Create: `go/internal/workflow/loader_test.go`
- Create: `go/testdata/workflows/test_workflow.yaml`

**Step 1: Create test workflow**

```yaml
# go/testdata/workflows/test_workflow.yaml
type: workflow
name: test_workflow
description: Test workflow for Go PoC
input_types:
  - url

tasks:
  httpx:
    tech_detect: true

  nuclei:
    targets_:
      - url.url
    severity:
      - critical
      - high
```

**Step 2: Write the failing test**

```go
// go/internal/workflow/loader_test.go
package workflow

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad(t *testing.T) {
	wf, err := Load("../../testdata/workflows/test_workflow.yaml")
	require.NoError(t, err)

	assert.Equal(t, "test_workflow", wf.Name())
	assert.Equal(t, "workflow", wf.config.Type)
	assert.Contains(t, wf.config.InputTypes, "url")
}

func TestWorkflow_Tasks(t *testing.T) {
	wf, err := Load("../../testdata/workflows/test_workflow.yaml")
	require.NoError(t, err)

	tasks := wf.TaskNames()
	assert.Contains(t, tasks, "httpx")
	assert.Contains(t, tasks, "nuclei")
}
```

**Step 3: Write implementation**

```go
// go/internal/workflow/loader.go
package workflow

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents the YAML workflow structure
type Config struct {
	Type        string                 `yaml:"type"`
	Name        string                 `yaml:"name"`
	Description string                 `yaml:"description"`
	InputTypes  []string               `yaml:"input_types"`
	Options     map[string]OptionDef   `yaml:"options"`
	Tasks       map[string]interface{} `yaml:"tasks"`
}

// OptionDef defines a workflow option
type OptionDef struct {
	IsFlag  bool        `yaml:"is_flag"`
	Default interface{} `yaml:"default"`
	Help    string      `yaml:"help"`
}

// TaskNode represents a task in the workflow
type TaskNode struct {
	Name      string
	Type      NodeType
	Task      string
	Options   map[string]any
	Targets   []string // e.g., ["url.url"]
	Condition string
	Children  []*TaskNode
}

// NodeType distinguishes task types
type NodeType int

const (
	TaskType NodeType = iota
	GroupType
	ChainType
)

// Workflow represents a loaded workflow
type Workflow struct {
	config Config
	root   *TaskNode
}

// Load parses a workflow YAML file
func Load(path string) (*Workflow, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	if cfg.Type != "workflow" {
		return nil, fmt.Errorf("expected type 'workflow', got '%s'", cfg.Type)
	}

	root := parseTaskTree(cfg.Tasks)
	return &Workflow{config: cfg, root: root}, nil
}

// Name returns the workflow name
func (w *Workflow) Name() string {
	return w.config.Name
}

// TaskNames returns all task names in the workflow
func (w *Workflow) TaskNames() []string {
	var names []string
	collectTaskNames(w.root, &names)
	return names
}

func collectTaskNames(node *TaskNode, names *[]string) {
	if node == nil {
		return
	}
	if node.Type == TaskType && node.Task != "" {
		*names = append(*names, node.Task)
	}
	for _, child := range node.Children {
		collectTaskNames(child, names)
	}
}

func parseTaskTree(tasks map[string]interface{}) *TaskNode {
	root := &TaskNode{Type: ChainType}

	for name, spec := range tasks {
		if name == "_group" {
			// Parallel group
			group := &TaskNode{Type: GroupType}
			if groupTasks, ok := spec.(map[string]any); ok {
				for childName, childSpec := range groupTasks {
					group.Children = append(group.Children, parseTaskNode(childName, childSpec))
				}
			}
			root.Children = append(root.Children, group)
		} else {
			// Sequential task
			root.Children = append(root.Children, parseTaskNode(name, spec))
		}
	}

	return root
}

func parseTaskNode(name string, spec interface{}) *TaskNode {
	node := &TaskNode{
		Type:    TaskType,
		Name:    name,
		Task:    name,
		Options: make(map[string]any),
	}

	if opts, ok := spec.(map[string]any); ok {
		for k, v := range opts {
			if k == "targets_" {
				if targets, ok := v.([]any); ok {
					for _, t := range targets {
						if s, ok := t.(string); ok {
							node.Targets = append(node.Targets, s)
						}
					}
				}
			} else if k == "if" {
				if cond, ok := v.(string); ok {
					node.Condition = cond
				}
			} else {
				node.Options[k] = v
			}
		}
	}

	return node
}
```

**Step 4: Run test**

Run: `cd /home/jahmyst/Workspace/secator/go && go mod tidy && go test ./internal/workflow/... -v`
Expected: PASS

**Step 5: Commit**

```bash
git add go/
git commit -m "feat(go): add workflow YAML loader"
```

---

## Task 18: Workflow Executor

**Files:**
- Create: `go/internal/workflow/executor.go`
- Create: `go/internal/workflow/executor_test.go`
- Modify: `go/cmd/secator/workflow.go`

**Step 1: Write executor**

```go
// go/internal/workflow/executor.go
package workflow

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/freelabz/secator/internal/engine"
	"github.com/freelabz/secator/internal/tasks"
	"github.com/freelabz/secator/pkg/types"
)

// Run executes the workflow
func (w *Workflow) Run(ctx context.Context, inputs []string) <-chan types.OutputType {
	out := make(chan types.OutputType, 100)

	go func() {
		defer close(out)

		// Track results by type for target extraction
		results := make(map[string][]types.OutputType)
		results["_input"] = toTargets(inputs)

		w.executeNode(ctx, w.root, results, out)
	}()

	return out
}

func (w *Workflow) Status() engine.Status {
	return engine.StatusSuccess
}

func (w *Workflow) executeNode(ctx context.Context, node *TaskNode, results map[string][]types.OutputType, out chan<- types.OutputType) {
	if node == nil {
		return
	}

	switch node.Type {
	case TaskType:
		w.executeTask(ctx, node, results, out)

	case GroupType:
		// Parallel execution
		var wg sync.WaitGroup
		var mu sync.Mutex

		for _, child := range node.Children {
			wg.Add(1)
			go func(n *TaskNode) {
				defer wg.Done()
				w.executeNode(ctx, n, results, out)
			}(child)
		}
		wg.Wait()
		_ = mu // Used for merging results if needed

	case ChainType:
		// Sequential execution
		for _, child := range node.Children {
			w.executeNode(ctx, child, results, out)
		}
	}
}

func (w *Workflow) executeTask(ctx context.Context, node *TaskNode, results map[string][]types.OutputType, out chan<- types.OutputType) {
	task, ok := tasks.Get(node.Task)
	if !ok {
		out <- types.NewError(fmt.Sprintf("unknown task: %s", node.Task))
		return
	}

	// Apply options
	task.SetOptions(node.Options)

	// Extract inputs from previous results
	inputs := extractInputs(node.Targets, results)
	if len(inputs) == 0 {
		// Use original inputs
		inputs = extractInputs([]string{"_input"}, results)
	}

	if len(inputs) == 0 {
		out <- types.NewInfo(fmt.Sprintf("skipping %s: no inputs", node.Task))
		return
	}

	// Execute task
	for r := range task.Run(ctx, inputs) {
		// Track result for downstream tasks
		typeName := r.Type()
		results[typeName] = append(results[typeName], r)

		// Emit to caller
		out <- r
	}
}

// extractInputs gets values from previous results
// e.g., "url.url" extracts URL field from all URL outputs
func extractInputs(targets []string, results map[string][]types.OutputType) []string {
	var inputs []string

	for _, target := range targets {
		parts := strings.Split(target, ".")
		typeName := parts[0]
		field := "value"
		if len(parts) > 1 {
			field = parts[1]
		}

		for _, r := range results[typeName] {
			m := r.ToMap()
			if v, ok := m[field].(string); ok {
				inputs = append(inputs, v)
			}
		}
	}

	return inputs
}

func toTargets(inputs []string) []types.OutputType {
	var targets []types.OutputType
	for _, input := range inputs {
		t := &types.Info{Message: input}
		t.SetSource("input")
		targets = append(targets, t)
	}
	return targets
}
```

**Step 2: Add workflow command**

```go
// go/cmd/secator/workflow.go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/freelabz/secator/internal/workflow"
	"github.com/spf13/cobra"
)

var workflowCmd = &cobra.Command{
	Use:     "w [workflow] [targets...]",
	Aliases: []string{"workflow"},
	Short:   "Run a workflow",
	Args:    cobra.MinimumNArgs(2),
	Run:     runWorkflow,
}

func init() {
	rootCmd.AddCommand(workflowCmd)
}

func runWorkflow(cmd *cobra.Command, args []string) {
	workflowName := args[0]
	targets := args[1:]

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// Try to find workflow file
	paths := []string{
		workflowName,
		workflowName + ".yaml",
		filepath.Join("configs", "workflows", workflowName+".yaml"),
	}

	var wf *workflow.Workflow
	var err error
	for _, p := range paths {
		wf, err = workflow.Load(p)
		if err == nil {
			break
		}
	}

	if wf == nil {
		fmt.Fprintf(os.Stderr, "Workflow not found: %s\n", workflowName)
		os.Exit(1)
	}

	jsonOutput, _ := cmd.Flags().GetBool("json")

	for result := range wf.Run(ctx, targets) {
		if jsonOutput {
			data, _ := json.Marshal(result.ToMap())
			fmt.Println(string(data))
		} else {
			fmt.Printf("[%s] %v\n", result.Type(), result.ToMap())
		}
	}
}
```

**Step 3: Build and test**

Run: `cd /home/jahmyst/Workspace/secator/go && go build -o bin/secator ./cmd/secator`
Expected: PASS

**Step 4: Commit**

```bash
git add go/
git commit -m "feat(go): add workflow executor and CLI command"
```

---

## Task 19: Broker Interface & Machinery

**Files:**
- Create: `go/internal/broker/broker.go`
- Create: `go/internal/broker/machinery/machinery.go`

**Step 1: Write broker interface**

```go
// go/internal/broker/broker.go
package broker

import (
	"context"

	"github.com/freelabz/secator/pkg/types"
)

// JobID identifies a queued job
type JobID string

// JobStatus represents job state
type JobStatus string

const (
	JobPending JobStatus = "pending"
	JobRunning JobStatus = "running"
	JobSuccess JobStatus = "success"
	JobFailure JobStatus = "failure"
)

// TaskHandler is a function that executes a task
type TaskHandler func(ctx context.Context, inputs []string, opts map[string]any) ([]types.OutputType, error)

// WorkflowSpec defines a workflow for distributed execution
type WorkflowSpec struct {
	Name  string
	Nodes []NodeSpec
}

// NodeSpec defines a node in the workflow
type NodeSpec struct {
	Type     string // "task", "group", "chain"
	TaskName string
	Inputs   []string
	OptsJSON string
	Children []NodeSpec
}

// Broker abstracts distributed task execution
type Broker interface {
	RegisterTask(name string, handler TaskHandler) error
	Enqueue(ctx context.Context, task string, inputs []string, opts map[string]any) (JobID, error)
	EnqueueWorkflow(ctx context.Context, w WorkflowSpec) (JobID, error)
	Results(ctx context.Context, jobID JobID) (<-chan types.OutputType, error)
	Status(ctx context.Context, jobID JobID) (JobStatus, error)
	StartWorker(ctx context.Context, concurrency int) error
	Close() error
}
```

**Step 2: Write Machinery implementation**

```go
// go/internal/broker/machinery/machinery.go
package machinery

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/RichardKnop/machinery/v2"
	"github.com/RichardKnop/machinery/v2/config"
	"github.com/RichardKnop/machinery/v2/tasks"
	"github.com/freelabz/secator/internal/broker"
	"github.com/freelabz/secator/pkg/types"
)

// Config for Machinery
type Config struct {
	BrokerURL     string `yaml:"broker_url"`     // redis://localhost:6379
	ResultBackend string `yaml:"result_backend"` // redis://localhost:6379
	DefaultQueue  string `yaml:"default_queue"`
	ResultsTTL    int    `yaml:"results_ttl"`
}

// Broker implements broker.Broker using Machinery
type Broker struct {
	server   *machinery.Server
	handlers map[string]broker.TaskHandler
}

// New creates a new Machinery broker
func New(cfg Config) (*Broker, error) {
	mcfg := &config.Config{
		Broker:          cfg.BrokerURL,
		DefaultQueue:    cfg.DefaultQueue,
		ResultBackend:   cfg.ResultBackend,
		ResultsExpireIn: cfg.ResultsTTL,
	}

	server, err := machinery.NewServer(mcfg)
	if err != nil {
		return nil, err
	}

	return &Broker{
		server:   server,
		handlers: make(map[string]broker.TaskHandler),
	}, nil
}

// RegisterTask registers a task handler
func (b *Broker) RegisterTask(name string, handler broker.TaskHandler) error {
	b.handlers[name] = handler

	return b.server.RegisterTask(name, func(inputsJSON, optsJSON string) (string, error) {
		var inputs []string
		var opts map[string]any

		json.Unmarshal([]byte(inputsJSON), &inputs)
		json.Unmarshal([]byte(optsJSON), &opts)

		ctx := context.Background()
		results, err := handler(ctx, inputs, opts)
		if err != nil {
			return "", err
		}

		// Serialize results
		var output []map[string]any
		for _, r := range results {
			output = append(output, r.ToMap())
		}

		data, _ := json.Marshal(output)
		return string(data), nil
	})
}

// Enqueue submits a task for execution
func (b *Broker) Enqueue(ctx context.Context, task string, inputs []string, opts map[string]any) (broker.JobID, error) {
	inputsJSON, _ := json.Marshal(inputs)
	optsJSON, _ := json.Marshal(opts)

	sig := &tasks.Signature{
		Name: task,
		Args: []tasks.Arg{
			{Type: "string", Value: string(inputsJSON)},
			{Type: "string", Value: string(optsJSON)},
		},
	}

	result, err := b.server.SendTask(sig)
	if err != nil {
		return "", err
	}

	return broker.JobID(result.GetState().TaskUUID), nil
}

// EnqueueWorkflow submits a workflow for execution
func (b *Broker) EnqueueWorkflow(ctx context.Context, spec broker.WorkflowSpec) (broker.JobID, error) {
	var sigs []*tasks.Signature

	for _, node := range spec.Nodes {
		sig := &tasks.Signature{
			Name: node.TaskName,
			Args: []tasks.Arg{
				{Type: "string", Value: mustJSON(node.Inputs)},
				{Type: "string", Value: node.OptsJSON},
			},
		}
		sigs = append(sigs, sig)
	}

	chain, err := tasks.NewChain(sigs...)
	if err != nil {
		return "", err
	}

	result, err := b.server.SendChain(chain)
	if err != nil {
		return "", err
	}

	return broker.JobID(result.GetState().TaskUUID), nil
}

// Results returns results for a job (blocking)
func (b *Broker) Results(ctx context.Context, jobID broker.JobID) (<-chan types.OutputType, error) {
	out := make(chan types.OutputType)

	go func() {
		defer close(out)
		// Implementation would poll for results
		// For now, just close the channel
	}()

	return out, nil
}

// Status returns the status of a job
func (b *Broker) Status(ctx context.Context, jobID broker.JobID) (broker.JobStatus, error) {
	// Implementation would check job state
	return broker.JobPending, nil
}

// StartWorker starts a worker
func (b *Broker) StartWorker(ctx context.Context, concurrency int) error {
	worker := b.server.NewWorker("secator-worker", concurrency)

	errCh := make(chan error)
	go func() {
		errCh <- worker.Launch()
	}()

	select {
	case <-ctx.Done():
		worker.Quit()
		return nil
	case err := <-errCh:
		return err
	}
}

// Close closes the broker
func (b *Broker) Close() error {
	return nil
}

func mustJSON(v any) string {
	data, _ := json.Marshal(v)
	return string(data)
}
```

**Step 3: Update go.mod with dependencies**

Run: `cd /home/jahmyst/Workspace/secator/go && go get github.com/RichardKnop/machinery/v2 && go mod tidy`

**Step 4: Commit**

```bash
git add go/
git commit -m "feat(go): add Broker interface and Machinery implementation"
```

---

## Task 20: Comparison Benchmark

**Files:**
- Create: `go/benchmark/comparison_test.go`
- Create: `go/scripts/compare.sh`

**Step 1: Write benchmark**

```go
// go/benchmark/comparison_test.go
package benchmark

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOutputCompatibility(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping comparison test")
	}

	target := "https://httpbin.org/get"

	// Run Python secator
	pyCmd := exec.Command("secator", "x", "httpx", target, "--json")
	pyOut, err := pyCmd.Output()
	if err != nil {
		t.Skipf("Python secator not available: %v", err)
	}

	// Run Go secator
	goCmd := exec.Command("./bin/secator", "x", "httpx", target, "--json")
	goOut, err := goCmd.Output()
	require.NoError(t, err)

	// Parse outputs
	pyResults := parseJSONLines(pyOut)
	goResults := parseJSONLines(goOut)

	// Compare key fields
	if len(pyResults) > 0 && len(goResults) > 0 {
		assert.Equal(t, pyResults[0]["_type"], goResults[0]["_type"])
		// URLs might differ slightly, but type should match
	}
}

func BenchmarkHttpxParse(b *testing.B) {
	data, err := os.ReadFile("../testdata/httpx_output.json")
	if err != nil {
		b.Skip("fixture not found")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var result map[string]any
		json.Unmarshal(data, &result)
	}
}

func parseJSONLines(data []byte) []map[string]any {
	var results []map[string]any
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		var obj map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &obj); err == nil {
			results = append(results, obj)
		}
	}
	return results
}
```

**Step 2: Write comparison script**

```bash
#!/bin/bash
# go/scripts/compare.sh

set -e

TARGET="${1:-https://httpbin.org/get}"
TASK="${2:-httpx}"

echo "=== Comparing Python vs Go secator ==="
echo "Task: $TASK"
echo "Target: $TARGET"
echo

cd "$(dirname "$0")/.."

# Build Go binary
echo "Building Go secator..."
go build -o bin/secator ./cmd/secator

# Run Python
echo
echo "Running Python secator..."
time secator x $TASK $TARGET --json > /tmp/py_output.json 2>/dev/null || true

# Run Go
echo
echo "Running Go secator..."
time ./bin/secator x $TASK $TARGET --json > /tmp/go_output.json 2>/dev/null || true

# Compare
echo
echo "=== Output Comparison ==="
echo "Python results: $(wc -l < /tmp/py_output.json) lines"
echo "Go results: $(wc -l < /tmp/go_output.json) lines"

echo
echo "=== Sample Python output ==="
head -1 /tmp/py_output.json | jq . 2>/dev/null || head -1 /tmp/py_output.json

echo
echo "=== Sample Go output ==="
head -1 /tmp/go_output.json | jq . 2>/dev/null || head -1 /tmp/go_output.json
```

**Step 3: Make script executable**

```bash
chmod +x go/scripts/compare.sh
```

**Step 4: Commit**

```bash
git add go/
git commit -m "feat(go): add comparison benchmarks and scripts"
```

---

## Task 21: Final Integration Test

**Files:**
- Create: `go/integration_test.go`

**Step 1: Write integration test**

```go
// go/integration_test.go
package main

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/freelabz/secator/internal/tasks"
	_ "github.com/freelabz/secator/internal/tasks/httpx"
	_ "github.com/freelabz/secator/internal/tasks/nuclei"
	"github.com/freelabz/secator/internal/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTaskRegistry(t *testing.T) {
	names := tasks.Names()
	assert.Contains(t, names, "httpx")
	assert.Contains(t, names, "nuclei")
}

func TestHttpxTask(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	// Check if httpx is installed
	if _, err := exec.LookPath("httpx"); err != nil {
		t.Skip("httpx not installed")
	}

	task, ok := tasks.Get("httpx")
	require.True(t, ok)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var results []string
	for r := range task.Run(ctx, []string{"https://httpbin.org/get"}) {
		results = append(results, r.Type())
	}

	assert.NotEmpty(t, results)
}

func TestWorkflowLoad(t *testing.T) {
	wf, err := workflow.Load("testdata/workflows/test_workflow.yaml")
	require.NoError(t, err)
	assert.Equal(t, "test_workflow", wf.Name())
}

func TestBinaryBuild(t *testing.T) {
	cmd := exec.Command("go", "build", "-o", "bin/secator", "./cmd/secator")
	err := cmd.Run()
	require.NoError(t, err)
}

func TestBinaryHelp(t *testing.T) {
	cmd := exec.Command("./bin/secator", "--help")
	output, err := cmd.Output()
	require.NoError(t, err)
	assert.Contains(t, string(output), "secator")
	assert.Contains(t, string(output), "task")
}
```

**Step 2: Run all tests**

Run: `cd /home/jahmyst/Workspace/secator/go && go test ./... -v`
Expected: All tests pass

**Step 3: Final commit**

```bash
git add go/
git commit -m "feat(go): add integration tests - PoC complete"
```

---

## Summary

The PoC is complete when all 21 tasks are done. Final verification:

```bash
cd /home/jahmyst/Workspace/secator/go

# Run all tests
go test ./... -v

# Build binary
go build -o bin/secator ./cmd/secator

# Test CLI
./bin/secator --help
./bin/secator health
./bin/secator x httpx https://httpbin.org/get --json

# Run comparison (if Python secator available)
./scripts/compare.sh
```

**Success criteria validation:**
1. **Performance** — Run `./scripts/compare.sh` to benchmark
2. **Code simplicity** — Review `go/` directory structure
3. **Deployment** — Single binary at `go/bin/secator`
4. **Output compatibility** — JSON format matches Python
5. **Workflow compatibility** — Test with Python workflow YAML files
