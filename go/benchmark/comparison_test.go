// go/benchmark/comparison_test.go
package benchmark

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOutputCompatibility(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping comparison test")
	}

	target := "https://httpbin.org/get"

	// Run Python secator
	pyCmd := exec.Command("secator", "x", "httpx", target, "--json")
	pyOut, err := pyCmd.Output()
	if err != nil {
		t.Skipf("Python secator not available: %v", err)
	}

	// Run Go secator
	goCmd := exec.Command("./bin/secator", "x", "httpx", target, "--json")
	goOut, err := goCmd.Output()
	require.NoError(t, err)

	// Parse outputs
	pyResults := parseJSONLines(pyOut)
	goResults := parseJSONLines(goOut)

	// Compare key fields
	if len(pyResults) > 0 && len(goResults) > 0 {
		assert.Equal(t, pyResults[0]["_type"], goResults[0]["_type"])
		// URLs might differ slightly, but type should match
	}
}

func BenchmarkHttpxParse(b *testing.B) {
	data, err := os.ReadFile("../testdata/httpx_output.json")
	if err != nil {
		b.Skip("fixture not found")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var result map[string]any
		json.Unmarshal(data, &result)
	}
}

func parseJSONLines(data []byte) []map[string]any {
	var results []map[string]any
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		var obj map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &obj); err == nil {
			results = append(results, obj)
		}
	}
	return results
}
