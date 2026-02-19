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
