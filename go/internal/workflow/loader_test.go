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
	assert.Contains(t, tasks, "katana")
}

func TestWorkflow_ParallelGroups(t *testing.T) {
	wf, err := Load("../../testdata/workflows/test_workflow.yaml")
	require.NoError(t, err)

	// Find the _group/test node
	var groupNode *TaskNode
	for _, child := range wf.root.Children {
		if child.Type == GroupType && child.Name == "_group/test" {
			groupNode = child
			break
		}
	}

	require.NotNil(t, groupNode, "expected _group/test node to exist")
	assert.Equal(t, GroupType, groupNode.Type)
	assert.Len(t, groupNode.Children, 2, "expected 2 parallel tasks in group")

	// Verify both tasks exist in the group
	taskNames := make([]string, len(groupNode.Children))
	for i, child := range groupNode.Children {
		taskNames[i] = child.Task
	}
	assert.Contains(t, taskNames, "nuclei")
	assert.Contains(t, taskNames, "katana")
}

func TestWorkflow_ComplexTargets(t *testing.T) {
	wf, err := Load("../../testdata/workflows/test_workflow.yaml")
	require.NoError(t, err)

	// Find the katana task which has complex targets
	var katanaNode *TaskNode
	for _, child := range wf.root.Children {
		if child.Type == GroupType {
			for _, groupChild := range child.Children {
				if groupChild.Task == "katana" {
					katanaNode = groupChild
					break
				}
			}
		}
	}

	require.NotNil(t, katanaNode, "expected katana task to exist")
	require.Len(t, katanaNode.TargetDefs, 1, "expected 1 target definition")

	// Verify the complex target definition
	targetDef := katanaNode.TargetDefs[0]
	assert.False(t, targetDef.IsSimple(), "expected complex target, not simple")
	assert.Equal(t, "url", targetDef.Type)
	assert.Equal(t, "url", targetDef.Field)
	assert.Equal(t, "item.status_code == 200", targetDef.Condition)
}

func TestWorkflow_SimpleTargets(t *testing.T) {
	wf, err := Load("../../testdata/workflows/test_workflow.yaml")
	require.NoError(t, err)

	// Find the nuclei task which has simple targets
	var nucleiNode *TaskNode
	for _, child := range wf.root.Children {
		if child.Type == GroupType {
			for _, groupChild := range child.Children {
				if groupChild.Task == "nuclei" {
					nucleiNode = groupChild
					break
				}
			}
		}
	}

	require.NotNil(t, nucleiNode, "expected nuclei task to exist")
	require.Len(t, nucleiNode.TargetDefs, 1, "expected 1 target definition")

	// Verify the simple target definition
	targetDef := nucleiNode.TargetDefs[0]
	assert.True(t, targetDef.IsSimple(), "expected simple target")
	assert.Equal(t, "url.url", targetDef.Simple)

	// Also verify backward compatibility with Targets slice
	assert.Contains(t, nucleiNode.Targets, "url.url")
}

func TestParseTargetDef_String(t *testing.T) {
	def := parseTargetDef("url.url")
	assert.True(t, def.IsSimple())
	assert.Equal(t, "url.url", def.Simple)
}

func TestParseTargetDef_Dict(t *testing.T) {
	input := map[string]any{
		"type":      "subdomain",
		"field":     "host",
		"condition": "not item.verified",
	}
	def := parseTargetDef(input)
	assert.False(t, def.IsSimple())
	assert.Equal(t, "subdomain", def.Type)
	assert.Equal(t, "host", def.Field)
	assert.Equal(t, "not item.verified", def.Condition)
}
