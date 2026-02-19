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
