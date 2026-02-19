// go/internal/engine/executor.go
package engine

import (
	"bufio"
	"context"
	"io"
	"os/exec"
	"strings"
)

// Executor runs external commands with streaming output
type Executor struct {
	command string
	args    []string
	stdin   []string
	env     []string
}

// NewExecutor creates a new executor for a command
func NewExecutor(command string, args []string) *Executor {
	return &Executor{
		command: command,
		args:    args,
	}
}

// SetStdin sets lines to write to stdin
func (e *Executor) SetStdin(lines []string) {
	e.stdin = lines
}

// SetEnv sets environment variables
func (e *Executor) SetEnv(env []string) {
	e.env = env
}

// Run executes the command and streams stdout lines
func (e *Executor) Run(ctx context.Context) (<-chan string, error) {
	cmd := exec.CommandContext(ctx, e.command, e.args...)

	if len(e.env) > 0 {
		cmd.Env = e.env
	}

	var stdin io.WriteCloser
	var err error
	if len(e.stdin) > 0 {
		stdin, err = cmd.StdinPipe()
		if err != nil {
			return nil, err
		}
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	out := make(chan string, 100)

	go func() {
		defer close(out)

		// Write stdin if provided
		if stdin != nil {
			go func() {
				for _, line := range e.stdin {
					stdin.Write([]byte(line + "\n"))
				}
				stdin.Close()
			}()
		}

		// Read stdout
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				select {
				case out <- line:
				case <-ctx.Done():
					return
				}
			}
		}

		cmd.Wait()
	}()

	return out, nil
}
