// go/internal/workflow/executor_test.go
package workflow

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/freelabz/secator/internal/engine"
	"github.com/freelabz/secator/internal/tasks"
	"github.com/freelabz/secator/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockTask implements engine.Task for testing
type mockTask struct {
	name        string
	inputType   string
	outputTypes []string
	results     []types.OutputType
	options     map[string]any
	runCount    atomic.Int32
	delay       time.Duration
}

func newMockTask(name string, results []types.OutputType) *mockTask {
	return &mockTask{
		name:        name,
		inputType:   "url",
		outputTypes: []string{"url"},
		results:     results,
		options:     make(map[string]any),
	}
}

func (m *mockTask) Name() string                               { return m.name }
func (m *mockTask) Command() string                            { return m.name }
func (m *mockTask) InputType() string                          { return m.inputType }
func (m *mockTask) OutputTypes() []string                      { return m.outputTypes }
func (m *mockTask) Install() error                             { return nil }
func (m *mockTask) Parse(line []byte) ([]types.OutputType, error) { return nil, nil }
func (m *mockTask) Status() engine.Status                      { return engine.StatusSuccess }

func (m *mockTask) SetOptions(opts map[string]any) {
	for k, v := range opts {
		m.options[k] = v
	}
}

func (m *mockTask) Run(ctx context.Context, inputs []string) <-chan types.OutputType {
	out := make(chan types.OutputType, 100)
	m.runCount.Add(1)

	go func() {
		defer close(out)

		if m.delay > 0 {
			select {
			case <-time.After(m.delay):
			case <-ctx.Done():
				return
			}
		}

		for _, r := range m.results {
			select {
			case out <- r:
			case <-ctx.Done():
				return
			}
		}
	}()

	return out
}

func TestWorkflow_Run_SequentialExecution(t *testing.T) {
	// Register mock task factories that create results with proper sources
	tasks.Register("task1", func() engine.Task {
		url1 := &types.URL{URL: "http://example.com/page1"}
		url1.SetSource("task1")
		return newMockTask("task1", []types.OutputType{url1})
	})

	tasks.Register("task2", func() engine.Task {
		url2 := &types.URL{URL: "http://example.com/page2"}
		url2.SetSource("task2")
		return newMockTask("task2", []types.OutputType{url2})
	})

	// Create a workflow with sequential tasks
	wf := &Workflow{
		root: &TaskNode{
			Type: ChainType,
			Children: []*TaskNode{
				{Type: TaskType, Task: "task1", Options: make(map[string]any)},
				{Type: TaskType, Task: "task2", Options: make(map[string]any)},
			},
		},
	}

	// Run workflow
	ctx := context.Background()
	results := collectResults(wf.Run(ctx, []string{"http://test.com"}))

	// Should have info messages plus results
	// Check that we got results from both tasks
	hasTask1Result := false
	hasTask2Result := false
	for _, r := range results {
		if r.Type() == "url" {
			m := r.ToMap()
			if m["_source"] == "task1" {
				hasTask1Result = true
			}
			if m["_source"] == "task2" {
				hasTask2Result = true
			}
		}
	}
	assert.True(t, hasTask1Result, "expected result from task1")
	assert.True(t, hasTask2Result, "expected result from task2")
}

func TestWorkflow_Run_ParallelExecution(t *testing.T) {
	// Create mock task factories with delays to verify parallelism
	tasks.Register("parallel1", func() engine.Task {
		url1 := &types.URL{URL: "http://parallel1.com"}
		url1.SetSource("parallel1")
		task := newMockTask("parallel1", []types.OutputType{url1})
		task.delay = 50 * time.Millisecond
		return task
	})

	tasks.Register("parallel2", func() engine.Task {
		url2 := &types.URL{URL: "http://parallel2.com"}
		url2.SetSource("parallel2")
		task := newMockTask("parallel2", []types.OutputType{url2})
		task.delay = 50 * time.Millisecond
		return task
	})

	// Create a workflow with parallel tasks
	wf := &Workflow{
		root: &TaskNode{
			Type: ChainType,
			Children: []*TaskNode{
				{
					Type: GroupType,
					Children: []*TaskNode{
						{Type: TaskType, Task: "parallel1", Options: make(map[string]any)},
						{Type: TaskType, Task: "parallel2", Options: make(map[string]any)},
					},
				},
			},
		},
	}

	// Run workflow and time it
	ctx := context.Background()
	start := time.Now()
	results := collectResults(wf.Run(ctx, []string{"http://test.com"}))
	elapsed := time.Since(start)

	// If running in parallel, should take ~50ms, not ~100ms
	assert.Less(t, elapsed, 150*time.Millisecond, "parallel tasks should run concurrently")

	// Both tasks should have produced results
	hasTask1Result := false
	hasTask2Result := false
	for _, r := range results {
		if r.Type() == "url" {
			m := r.ToMap()
			if m["_source"] == "parallel1" {
				hasTask1Result = true
			}
			if m["_source"] == "parallel2" {
				hasTask2Result = true
			}
		}
	}
	assert.True(t, hasTask1Result, "expected result from parallel1")
	assert.True(t, hasTask2Result, "expected result from parallel2")
}

func TestWorkflow_Run_UnknownTask(t *testing.T) {
	// Create a workflow with an unknown task
	wf := &Workflow{
		root: &TaskNode{
			Type: ChainType,
			Children: []*TaskNode{
				{Type: TaskType, Task: "nonexistent_task", Options: make(map[string]any)},
			},
		},
	}

	ctx := context.Background()
	results := collectResults(wf.Run(ctx, []string{"http://test.com"}))

	// Should have an error result
	hasError := false
	for _, r := range results {
		if r.Type() == "error" {
			m := r.ToMap()
			if msg, ok := m["message"].(string); ok {
				if msg == "unknown task: nonexistent_task" {
					hasError = true
				}
			}
		}
	}
	assert.True(t, hasError, "expected error for unknown task")
}

func TestWorkflow_Run_ContextCancellation(t *testing.T) {
	// Create a task factory that takes a long time
	tasks.Register("slowtask", func() engine.Task {
		task := newMockTask("slowtask", []types.OutputType{})
		task.delay = 5 * time.Second
		return task
	})

	wf := &Workflow{
		root: &TaskNode{
			Type: ChainType,
			Children: []*TaskNode{
				{Type: TaskType, Task: "slowtask", Options: make(map[string]any)},
			},
		},
	}

	// Run with a context that will be cancelled
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_ = collectResults(wf.Run(ctx, []string{"http://test.com"}))
	elapsed := time.Since(start)

	// Should complete quickly due to cancellation, not wait 5 seconds
	assert.Less(t, elapsed, 1*time.Second, "workflow should respect context cancellation")
}

func TestExtractInputs_SimpleTarget(t *testing.T) {
	// Create result store with some URL results
	store := &resultStore{data: make(map[string][]types.OutputType)}

	url1 := &types.URL{URL: "http://example1.com"}
	url2 := &types.URL{URL: "http://example2.com"}
	store.set("url", []types.OutputType{url1, url2})

	// Extract using "url.url" pattern
	inputs := extractInputs([]string{"url.url"}, store)

	assert.Len(t, inputs, 2)
	assert.Contains(t, inputs, "http://example1.com")
	assert.Contains(t, inputs, "http://example2.com")
}

func TestExtractInputs_DefaultField(t *testing.T) {
	// Create result store with info results that have "value" in context
	store := &resultStore{data: make(map[string][]types.OutputType)}

	info1 := types.NewInfo("test1")
	info1.SetContext(map[string]any{"value": "input1"})
	info2 := types.NewInfo("test2")
	info2.SetContext(map[string]any{"value": "input2"})
	store.set("_input", []types.OutputType{info1, info2})

	// Extract using "_input" pattern (default field is "value")
	inputs := extractInputs([]string{"_input"}, store)

	assert.Len(t, inputs, 2)
	assert.Contains(t, inputs, "input1")
	assert.Contains(t, inputs, "input2")
}

func TestExtractInputs_EmptyResults(t *testing.T) {
	store := &resultStore{data: make(map[string][]types.OutputType)}

	inputs := extractInputs([]string{"nonexistent.field"}, store)

	assert.Empty(t, inputs)
}

func TestToTargets(t *testing.T) {
	targets := toTargets([]string{"http://a.com", "http://b.com"})

	require.Len(t, targets, 2)

	for i, target := range targets {
		assert.Equal(t, "info", target.Type())
		m := target.ToMap()
		assert.Equal(t, "input", m["_source"])
		ctx := m["_context"].(map[string]any)
		if i == 0 {
			assert.Equal(t, "http://a.com", ctx["value"])
		} else {
			assert.Equal(t, "http://b.com", ctx["value"])
		}
	}
}

func TestResultStore_Concurrent(t *testing.T) {
	store := &resultStore{data: make(map[string][]types.OutputType)}

	// Concurrently append results
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			info := types.NewInfo("test")
			store.append("key", info)
		}(i)
	}
	wg.Wait()

	// Should have all 100 results
	results := store.get("key")
	assert.Len(t, results, 100)
}

func TestWorkflow_Status(t *testing.T) {
	wf := &Workflow{}
	assert.Equal(t, engine.StatusSuccess, wf.Status())
}

// Helper to collect all results from a channel
func collectResults(ch <-chan types.OutputType) []types.OutputType {
	var results []types.OutputType
	for r := range ch {
		results = append(results, r)
	}
	return results
}
