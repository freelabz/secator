// go/internal/tasks/httpx/httpx_test.go
package httpx

import (
	"os"
	"testing"

	"github.com/freelabz/secator/internal/engine"
	"github.com/freelabz/secator/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHttpx_ImplementsTask(t *testing.T) {
	var _ engine.Task = &Httpx{}
}

func TestHttpx_Command(t *testing.T) {
	h := New()
	// Note: Command returns "httpx-toolkit" to avoid conflict with Python httpx library
	assert.Equal(t, "httpx-toolkit", h.Command())
}

func TestHttpx_InputType(t *testing.T) {
	h := New()
	assert.Equal(t, "url", h.InputType())
}

func TestHttpx_OutputTypes(t *testing.T) {
	h := New()
	outputs := h.OutputTypes()
	assert.Contains(t, outputs, "url")
	assert.Contains(t, outputs, "subdomain")
	assert.Contains(t, outputs, "certificate")
}

func TestHttpx_Parse(t *testing.T) {
	h := New()

	data, err := os.ReadFile("../../../testdata/httpx_output.json")
	require.NoError(t, err)

	results, err := h.Parse(data)
	require.NoError(t, err)
	require.NotEmpty(t, results)

	// First result should be URL
	url, ok := results[0].(*types.URL)
	require.True(t, ok)
	assert.Equal(t, "https://media.example.synology.me:443", url.URL)
	assert.Equal(t, 200, url.StatusCode)
	assert.Contains(t, url.Technologies, "Nginx")
}

func TestHttpx_BuildArgs(t *testing.T) {
	h := New()
	h.SetOptions(map[string]any{
		"tech_detect": true,
		"threads":     50,
	})

	args := h.BuildArgs()
	assert.Contains(t, args, "-json")
	assert.Contains(t, args, "-silent")
	assert.Contains(t, args, "-tech-detect")
	assert.Contains(t, args, "-threads")
}

func TestHttpx_Name(t *testing.T) {
	h := New()
	assert.Equal(t, "httpx", h.Name())
}

func TestHttpx_Status(t *testing.T) {
	h := New()
	assert.Equal(t, engine.StatusPending, h.Status())
}

func TestHttpx_DefaultOptions(t *testing.T) {
	h := New()
	args := h.BuildArgs()

	// Check default args are present
	assert.Contains(t, args, "-json")
	assert.Contains(t, args, "-silent")
	assert.Contains(t, args, "-threads")
	assert.Contains(t, args, "-timeout")
}

func TestHttpx_SetOptions(t *testing.T) {
	h := New()
	h.SetOptions(map[string]any{
		"tech_detect":      true,
		"tls_grab":         true,
		"threads":          100,
		"rate_limit":       50,
		"timeout":          30,
		"follow_redirects": true,
		"headers":          []string{"User-Agent: test"},
	})

	args := h.BuildArgs()
	assert.Contains(t, args, "-tech-detect")
	assert.Contains(t, args, "-tls-grab")
	assert.Contains(t, args, "-follow-redirects")
	assert.Contains(t, args, "-H")
}

func TestHttpx_Install(t *testing.T) {
	h := New()
	err := h.Install()
	assert.NoError(t, err)
}
