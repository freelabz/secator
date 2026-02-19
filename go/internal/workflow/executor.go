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
		results := &resultStore{
			data: make(map[string][]types.OutputType),
		}
		results.set("_input", toTargets(inputs))

		w.executeNode(ctx, w.root, results, out)
	}()

	return out
}

// Status returns the workflow execution status
func (w *Workflow) Status() engine.Status {
	return engine.StatusSuccess
}

// resultStore provides thread-safe access to results
type resultStore struct {
	mu   sync.RWMutex
	data map[string][]types.OutputType
}

func (r *resultStore) get(key string) []types.OutputType {
	r.mu.RLock()
	defer r.mu.RUnlock()
	original := r.data[key]
	if original == nil {
		return nil
	}
	copied := make([]types.OutputType, len(original))
	copy(copied, original)
	return copied
}

func (r *resultStore) set(key string, values []types.OutputType) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.data[key] = values
}

func (r *resultStore) append(key string, value types.OutputType) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.data[key] = append(r.data[key], value)
}

func (r *resultStore) keys() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	keys := make([]string, 0, len(r.data))
	for k := range r.data {
		keys = append(keys, k)
	}
	return keys
}

func (w *Workflow) executeNode(ctx context.Context, node *TaskNode, results *resultStore, out chan<- types.OutputType) {
	if node == nil {
		return
	}

	// Check for context cancellation
	select {
	case <-ctx.Done():
		return
	default:
	}

	switch node.Type {
	case TaskType:
		w.executeTask(ctx, node, results, out)

	case GroupType:
		// Parallel execution
		var wg sync.WaitGroup

		for _, child := range node.Children {
			wg.Add(1)
			go func(n *TaskNode) {
				defer wg.Done()
				w.executeNode(ctx, n, results, out)
			}(child)
		}
		wg.Wait()

	case ChainType:
		// Sequential execution
		for _, child := range node.Children {
			select {
			case <-ctx.Done():
				return
			default:
				w.executeNode(ctx, child, results, out)
			}
		}
	}
}

func (w *Workflow) executeTask(ctx context.Context, node *TaskNode, results *resultStore, out chan<- types.OutputType) {
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

	// Emit info about starting task
	out <- types.NewInfo(fmt.Sprintf("running %s with %d inputs", node.Task, len(inputs)))

	// Execute task
	for r := range task.Run(ctx, inputs) {
		// Track result for downstream tasks
		typeName := r.Type()
		results.append(typeName, r)

		// Emit to caller
		select {
		case out <- r:
		case <-ctx.Done():
			return
		}
	}
}

// extractInputs gets values from previous results
// e.g., "url.url" extracts URL field from all URL outputs
// e.g., "_input" extracts value field from _context of info types
func extractInputs(targets []string, results *resultStore) []string {
	var inputs []string

	for _, target := range targets {
		parts := strings.Split(target, ".")
		typeName := parts[0]
		field := "value"
		if len(parts) > 1 {
			field = parts[1]
		}

		for _, r := range results.get(typeName) {
			m := r.ToMap()

			// First try direct field access
			if v, ok := m[field].(string); ok {
				inputs = append(inputs, v)
				continue
			}

			// Then try within _context (for stored input targets)
			if ctx, ok := m["_context"].(map[string]any); ok {
				if v, ok := ctx[field].(string); ok {
					inputs = append(inputs, v)
				}
			}
		}
	}

	return inputs
}

func toTargets(inputs []string) []types.OutputType {
	var targets []types.OutputType
	for _, input := range inputs {
		t := types.NewInfo(input)
		t.SetSource("input")
		// Store the value in a way that can be extracted
		t.SetContext(map[string]any{"value": input})
		targets = append(targets, t)
	}
	return targets
}
