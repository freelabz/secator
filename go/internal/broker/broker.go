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
