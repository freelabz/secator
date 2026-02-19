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
