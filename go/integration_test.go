// go/integration_test.go
package main

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/freelabz/secator/internal/tasks"
	_ "github.com/freelabz/secator/internal/tasks/httpx"
	_ "github.com/freelabz/secator/internal/tasks/nuclei"
	"github.com/freelabz/secator/internal/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTaskRegistry(t *testing.T) {
	names := tasks.Names()
	assert.Contains(t, names, "httpx")
	assert.Contains(t, names, "nuclei")
}

func TestHttpxTask(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	// Check if httpx is installed
	if _, err := exec.LookPath("httpx"); err != nil {
		t.Skip("httpx not installed")
	}

	task, ok := tasks.Get("httpx")
	require.True(t, ok)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var results []string
	for r := range task.Run(ctx, []string{"https://httpbin.org/get"}) {
		results = append(results, r.Type())
	}

	assert.NotEmpty(t, results)
}

func TestWorkflowLoad(t *testing.T) {
	wf, err := workflow.Load("testdata/workflows/test_workflow.yaml")
	require.NoError(t, err)
	assert.Equal(t, "test_workflow", wf.Name())
}

func TestBinaryBuild(t *testing.T) {
	cmd := exec.Command("go", "build", "-o", "bin/secator", "./cmd/secator")
	err := cmd.Run()
	require.NoError(t, err)
}

func TestBinaryHelp(t *testing.T) {
	cmd := exec.Command("./bin/secator", "--help")
	output, err := cmd.Output()
	require.NoError(t, err)
	assert.Contains(t, string(output), "secator")
	assert.Contains(t, string(output), "task")
}
