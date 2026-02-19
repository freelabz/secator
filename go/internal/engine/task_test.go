// go/internal/engine/task_test.go
package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/freelabz/secator/pkg/types"
	"github.com/stretchr/testify/assert"
)

type mockTask struct {
	mockRunner
	cmd string
}

func (m *mockTask) Command() string                               { return m.cmd }
func (m *mockTask) Description() string                           { return "Mock task for testing" }
func (m *mockTask) InputType() string                             { return "url" }
func (m *mockTask) OutputTypes() []string                         { return []string{"url"} }
func (m *mockTask) Install() error                                { return nil }
func (m *mockTask) Parse(line []byte) ([]types.OutputType, error) { return nil, nil }
func (m *mockTask) SetOptions(opts map[string]any)                {}
func (m *mockTask) CmdLine(inputs []string) string                { return m.cmd + " " + strings.Join(inputs, " ") }

func TestTask_Interface(t *testing.T) {
	var _ Task = &mockTask{}
}

func TestTask_Command(t *testing.T) {
	task := &mockTask{cmd: "httpx"}
	assert.Equal(t, "httpx", task.Command())
}

func TestTask_InputType(t *testing.T) {
	task := &mockTask{}
	assert.Equal(t, "url", task.InputType())
}

func TestTask_OutputTypes(t *testing.T) {
	task := &mockTask{}
	assert.Equal(t, []string{"url"}, task.OutputTypes())
}

func TestTask_Install(t *testing.T) {
	task := &mockTask{}
	err := task.Install()
	assert.NoError(t, err)
}

func TestTask_Parse(t *testing.T) {
	task := &mockTask{}
	results, err := task.Parse([]byte("test line"))
	assert.NoError(t, err)
	assert.Nil(t, results)
}

func TestTask_SetOptions(t *testing.T) {
	task := &mockTask{}
	// Should not panic
	task.SetOptions(map[string]any{"key": "value"})
}

// Verify mockTask embeds Runner behavior
func TestTask_RunnerBehavior(t *testing.T) {
	task := &mockTask{
		mockRunner: mockRunner{name: "test-task"},
		cmd:        "httpx",
	}

	assert.Equal(t, "test-task", task.Name())
	assert.Equal(t, StatusSuccess, task.Status())

	ctx := context.Background()
	ch := task.Run(ctx, []string{"http://example.com"})

	// Drain channel
	for range ch {
	}
}
