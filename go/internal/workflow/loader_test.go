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
