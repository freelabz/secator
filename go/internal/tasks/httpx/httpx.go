// go/internal/tasks/httpx/httpx.go
package httpx

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
	tasks.Register("httpx", func() engine.Task { return New() })
}

// Options holds configuration for httpx
type Options struct {
	TechDetect      bool     `json:"tech_detect"`
	TLSGrab         bool     `json:"tls_grab"`
	StatusCode      bool     `json:"status_code"`
	Threads         int      `json:"threads"`
	RateLimit       int      `json:"rate_limit"`
	Timeout         int      `json:"timeout"`
	FollowRedirects bool     `json:"follow_redirects"`
	Headers         []string `json:"headers"`
}

// Httpx implements the engine.Task interface for the httpx tool
type Httpx struct {
	opts   Options
	status engine.Status
}

// New creates a new Httpx task with default options
func New() *Httpx {
	return &Httpx{
		opts:   Options{Threads: 50, Timeout: 10},
		status: engine.StatusPending,
	}
}

// Name returns the task name
func (h *Httpx) Name() string { return "httpx" }

// Command returns the CLI command name
// Note: The ProjectDiscovery httpx tool may be installed as "httpx" or "httpx-toolkit"
func (h *Httpx) Command() string {
	// Try httpx-toolkit first (common on systems where Python httpx is also installed)
	return "httpx-toolkit"
}

// Description returns the tool description
func (h *Httpx) Description() string { return "Fast and multi-purpose HTTP toolkit" }

// InputType returns the expected input type
func (h *Httpx) InputType() string { return "url" }

// Status returns the current execution status
func (h *Httpx) Status() engine.Status { return h.status }

// OutputTypes returns the types of outputs this task produces
func (h *Httpx) OutputTypes() []string { return []string{"url", "subdomain", "certificate"} }

// Install handles auto-installation of the httpx tool
func (h *Httpx) Install() error { return nil }

// SetOptions configures the task with the provided options
func (h *Httpx) SetOptions(opts map[string]any) {
	if v, ok := opts["tech_detect"].(bool); ok {
		h.opts.TechDetect = v
	}
	if v, ok := opts["tls_grab"].(bool); ok {
		h.opts.TLSGrab = v
	}
	if v, ok := opts["threads"].(int); ok {
		h.opts.Threads = v
	}
	if v, ok := opts["rate_limit"].(int); ok {
		h.opts.RateLimit = v
	}
	if v, ok := opts["timeout"].(int); ok {
		h.opts.Timeout = v
	}
	if v, ok := opts["follow_redirects"].(bool); ok {
		h.opts.FollowRedirects = v
	}
	if headers, ok := opts["headers"].([]string); ok {
		h.opts.Headers = headers
	}
}

// CmdLine returns the full command line for display
func (h *Httpx) CmdLine(inputs []string) string {
	args := h.BuildArgs()
	// Add -u flag for each input
	for _, input := range inputs {
		args = append(args, "-u", input)
	}
	return h.Command() + " " + strings.Join(args, " ")
}

// BuildArgs constructs the command line arguments for httpx
func (h *Httpx) BuildArgs() []string {
	args := []string{"-json", "-silent"}

	if h.opts.TechDetect {
		args = append(args, "-tech-detect")
	}
	if h.opts.TLSGrab {
		args = append(args, "-tls-grab")
	}
	if h.opts.Threads > 0 {
		args = append(args, "-threads", strconv.Itoa(h.opts.Threads))
	}
	if h.opts.RateLimit > 0 {
		args = append(args, "-rate-limit", strconv.Itoa(h.opts.RateLimit))
	}
	if h.opts.Timeout > 0 {
		args = append(args, "-timeout", strconv.Itoa(h.opts.Timeout))
	}
	if h.opts.FollowRedirects {
		args = append(args, "-follow-redirects")
	}
	for _, header := range h.opts.Headers {
		args = append(args, "-H", header)
	}

	return args
}

// Parse parses a single line of httpx JSON output into OutputTypes
func (h *Httpx) Parse(line []byte) ([]types.OutputType, error) {
	var raw map[string]any
	if err := json.Unmarshal(line, &raw); err != nil {
		return nil, err
	}

	url, err := types.URLFromMap(raw)
	if err != nil {
		return nil, err
	}
	url.SetSource("httpx")

	return []types.OutputType{url}, nil
}

// Run executes the httpx command with the given inputs and streams results
func (h *Httpx) Run(ctx context.Context, inputs []string) <-chan types.OutputType {
	out := make(chan types.OutputType, 100)

	go func() {
		defer close(out)
		h.status = engine.StatusRunning

		args := h.BuildArgs()
		exec := engine.NewExecutor(h.Command(), args)
		exec.SetStdin(inputs)

		lines, err := exec.Run(ctx)
		if err != nil {
			out <- types.NewError(err.Error())
			h.status = engine.StatusFailure
			return
		}

		for line := range lines {
			results, err := h.Parse([]byte(line))
			if err != nil {
				out <- types.NewError(err.Error())
				continue
			}
			for _, r := range results {
				select {
				case out <- r:
				case <-ctx.Done():
					h.status = engine.StatusRevoked
					return
				}
			}
		}
		h.status = engine.StatusSuccess
	}()

	return out
}
