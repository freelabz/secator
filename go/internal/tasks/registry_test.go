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
	assert.Nil(t, got) // factory returns nil
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
