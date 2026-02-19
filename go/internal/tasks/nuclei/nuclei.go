// go/internal/tasks/nuclei/nuclei.go
package nuclei

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/freelabz/secator/internal/engine"
	"github.com/freelabz/secator/internal/tasks"
	"github.com/freelabz/secator/pkg/types"
)

func init() {
	tasks.Register("nuclei", func() engine.Task { return New() })
}

// Options holds configuration for nuclei
type Options struct {
	Templates   []string `json:"templates"`
	Severity    []string `json:"severity"`
	Tags        []string `json:"tags"`
	ExcludeTags []string `json:"exclude_tags"`
	RateLimit   int      `json:"rate_limit"`
	Concurrency int      `json:"concurrency"`
	Timeout     int      `json:"timeout"`
}

// Nuclei implements the engine.Task interface for the nuclei tool
type Nuclei struct {
	opts   Options
	status engine.Status
}

// New creates a new Nuclei task with default options
func New() *Nuclei {
	return &Nuclei{
		opts:   Options{Concurrency: 25, RateLimit: 150, Timeout: 10},
		status: engine.StatusPending,
	}
}

// Name returns the task name
func (n *Nuclei) Name() string { return "nuclei" }

// Command returns the CLI command name
func (n *Nuclei) Command() string { return "nuclei" }

// Description returns the tool description
func (n *Nuclei) Description() string { return "Fast and customizable vulnerability scanner" }

// InputType returns the expected input type
func (n *Nuclei) InputType() string { return "url" }

// Status returns the current execution status
func (n *Nuclei) Status() engine.Status { return n.status }

// OutputTypes returns the types of outputs this task produces
func (n *Nuclei) OutputTypes() []string { return []string{"vulnerability"} }

// Install handles auto-installation of the nuclei tool
func (n *Nuclei) Install() error { return nil }

// SetOptions configures the task with the provided options
func (n *Nuclei) SetOptions(opts map[string]any) {
	if v, ok := opts["templates"].([]string); ok {
		n.opts.Templates = v
	}
	if v, ok := opts["severity"].([]string); ok {
		n.opts.Severity = v
	}
	if v, ok := opts["tags"].([]string); ok {
		n.opts.Tags = v
	}
	if v, ok := opts["exclude_tags"].([]string); ok {
		n.opts.ExcludeTags = v
	}
	if v, ok := opts["rate_limit"].(int); ok {
		n.opts.RateLimit = v
	}
	if v, ok := opts["concurrency"].(int); ok {
		n.opts.Concurrency = v
	}
	if v, ok := opts["timeout"].(int); ok {
		n.opts.Timeout = v
	}
}

// CmdLine returns the full command line for display
func (n *Nuclei) CmdLine(inputs []string) string {
	args := n.BuildArgs()
	// Add -u flag for each input
	for _, input := range inputs {
		args = append(args, "-u", input)
	}
	return n.Command() + " " + strings.Join(args, " ")
}

// BuildArgs constructs the command line arguments for nuclei
func (n *Nuclei) BuildArgs() []string {
	args := []string{"-jsonl", "-silent"}

	if len(n.opts.Templates) > 0 {
		args = append(args, "-t", strings.Join(n.opts.Templates, ","))
	}
	if len(n.opts.Severity) > 0 {
		args = append(args, "-severity", strings.Join(n.opts.Severity, ","))
	}
	if len(n.opts.Tags) > 0 {
		args = append(args, "-tags", strings.Join(n.opts.Tags, ","))
	}
	if len(n.opts.ExcludeTags) > 0 {
		args = append(args, "-exclude-tags", strings.Join(n.opts.ExcludeTags, ","))
	}
	if n.opts.RateLimit > 0 {
		args = append(args, "-rate-limit", strconv.Itoa(n.opts.RateLimit))
	}
	if n.opts.Concurrency > 0 {
		args = append(args, "-concurrency", strconv.Itoa(n.opts.Concurrency))
	}

	return args
}

// Parse parses a single line of nuclei JSON output into OutputTypes
func (n *Nuclei) Parse(line []byte) ([]types.OutputType, error) {
	var raw map[string]any
	if err := json.Unmarshal(line, &raw); err != nil {
		return nil, err
	}

	vuln, err := types.VulnerabilityFromMap(raw)
	if err != nil {
		return nil, err
	}
	vuln.SetSource("nuclei")

	return []types.OutputType{vuln}, nil
}

// Run executes the nuclei command with the given inputs and streams results
func (n *Nuclei) Run(ctx context.Context, inputs []string) <-chan types.OutputType {
	out := make(chan types.OutputType, 100)

	go func() {
		defer close(out)
		n.status = engine.StatusRunning

		args := n.BuildArgs()
		exec := engine.NewExecutor(n.Command(), args)
		exec.SetStdin(inputs)

		lines, err := exec.Run(ctx)
		if err != nil {
			out <- types.NewError(err.Error())
			n.status = engine.StatusFailure
			return
		}

		for line := range lines {
			results, err := n.Parse([]byte(line))
			if err != nil {
				// Skip non-JSON lines (nuclei outputs progress lines that aren't JSON)
				continue
			}
			for _, r := range results {
				select {
				case out <- r:
				case <-ctx.Done():
					n.status = engine.StatusRevoked
					return
				}
			}
		}
		n.status = engine.StatusSuccess
	}()

	return out
}
