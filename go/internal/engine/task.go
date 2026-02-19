// go/internal/engine/task.go
package engine

import (
	"github.com/freelabz/secator/pkg/types"
)

// Task wraps an external CLI tool
type Task interface {
	Runner
	Command() string                                 // e.g., "httpx"
	InputType() string                               // "url", "host", "ip"
	OutputTypes() []string                           // ["url", "subdomain"]
	Install() error                                  // Auto-installation
	Parse(line []byte) ([]types.OutputType, error)   // Parse single output line
	SetOptions(opts map[string]any)                  // Configure task options
}
