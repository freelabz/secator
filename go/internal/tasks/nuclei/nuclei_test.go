// go/internal/tasks/nuclei/nuclei_test.go
package nuclei

import (
	"os"
	"testing"

	"github.com/freelabz/secator/internal/engine"
	"github.com/freelabz/secator/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNuclei_ImplementsTask(t *testing.T) {
	var _ engine.Task = &Nuclei{}
}

func TestNuclei_Command(t *testing.T) {
	n := New()
	assert.Equal(t, "nuclei", n.Command())
}

func TestNuclei_Parse(t *testing.T) {
	n := New()

	data, err := os.ReadFile("../../../testdata/nuclei_output.json")
	require.NoError(t, err)

	results, err := n.Parse(data)
	require.NoError(t, err)
	require.Len(t, results, 1)

	vuln, ok := results[0].(*types.Vulnerability)
	require.True(t, ok)
	assert.Equal(t, "HTTP Missing Security Headers", vuln.Name)
	assert.Equal(t, "info", vuln.Severity)
	assert.Equal(t, "nuclei", vuln.Provider)
}

func TestNuclei_BuildArgs(t *testing.T) {
	n := New()
	n.SetOptions(map[string]any{
		"severity":   []string{"critical", "high"},
		"rate_limit": 100,
	})

	args := n.BuildArgs()
	assert.Contains(t, args, "-jsonl")
	assert.Contains(t, args, "-silent")
	assert.Contains(t, args, "-severity")
}

func TestNuclei_Name(t *testing.T) {
	n := New()
	assert.Equal(t, "nuclei", n.Name())
}

func TestNuclei_InputType(t *testing.T) {
	n := New()
	assert.Equal(t, "url", n.InputType())
}

func TestNuclei_OutputTypes(t *testing.T) {
	n := New()
	outputs := n.OutputTypes()
	assert.Contains(t, outputs, "vulnerability")
}

func TestNuclei_Status(t *testing.T) {
	n := New()
	assert.Equal(t, engine.StatusPending, n.Status())
}

func TestNuclei_DefaultOptions(t *testing.T) {
	n := New()
	args := n.BuildArgs()

	// Check default args are present
	assert.Contains(t, args, "-jsonl")
	assert.Contains(t, args, "-silent")
	assert.Contains(t, args, "-rate-limit")
	assert.Contains(t, args, "-concurrency")
}

func TestNuclei_SetOptions(t *testing.T) {
	n := New()
	n.SetOptions(map[string]any{
		"templates":    []string{"cves", "misconfigs"},
		"severity":     []string{"critical", "high", "medium"},
		"tags":         []string{"cve", "rce"},
		"exclude_tags": []string{"dos"},
		"rate_limit":   100,
		"concurrency":  50,
		"timeout":      30,
	})

	args := n.BuildArgs()
	assert.Contains(t, args, "-t")
	assert.Contains(t, args, "-severity")
	assert.Contains(t, args, "-tags")
	assert.Contains(t, args, "-exclude-tags")
	assert.Contains(t, args, "-rate-limit")
	assert.Contains(t, args, "-concurrency")
}

func TestNuclei_Install(t *testing.T) {
	n := New()
	err := n.Install()
	assert.NoError(t, err)
}

func TestNuclei_ParseInvalidJSON(t *testing.T) {
	n := New()

	// Test with invalid JSON (simulating progress lines)
	_, err := n.Parse([]byte("Scanning target: example.com"))
	assert.Error(t, err)

	// Test with empty input
	_, err = n.Parse([]byte(""))
	assert.Error(t, err)
}
