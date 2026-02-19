// go/cmd/secator/task.go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"github.com/freelabz/secator/internal/tasks"
	_ "github.com/freelabz/secator/internal/tasks/httpx"
	_ "github.com/freelabz/secator/internal/tasks/nuclei"
	"github.com/freelabz/secator/pkg/console"
	"github.com/spf13/cobra"
)

var taskCmd = &cobra.Command{
	Use:     "x [task] [targets...]",
	Aliases: []string{"t", "task"},
	Short:   "Run a task",
	Args:    cobra.MinimumNArgs(2),
	Run:     runTask,
}

func init() {
	rootCmd.AddCommand(taskCmd)
}

func runTask(cmd *cobra.Command, args []string) {
	taskName := args[0]
	targets := args[1:]

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	task, ok := tasks.Get(taskName)
	if !ok {
		fmt.Println(console.Err(fmt.Sprintf("Unknown task: %s", taskName)))
		fmt.Printf("Available tasks: %v\n", tasks.Names())
		os.Exit(1)
	}

	jsonOutput, _ := cmd.Flags().GetBool("json")

	// Print banner and task info (unless JSON mode)
	if !jsonOutput {
		fmt.Println(console.Banner(Version))
		fmt.Println(console.Info(fmt.Sprintf("Loaded %d target(s) for %s", len(targets), taskName)))
		for _, t := range targets {
			fmt.Println(console.Target(t, detectTargetType(t)))
		}
		fmt.Println(console.TaskStart(taskName, task.Description()))
		fmt.Println(console.Command(task.CmdLine(targets)))
	}

	count := 0
	for result := range task.Run(ctx, targets) {
		count++
		if jsonOutput {
			data, err := json.Marshal(result.ToMap())
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error marshaling result: %v\n", err)
				continue
			}
			fmt.Println(string(data))
		} else {
			fmt.Println(result.String())
		}
	}

	// Print task end (unless JSON mode)
	if !jsonOutput {
		fmt.Println(console.TaskEnd(taskName, "SUCCESS", count))
	}
}

// detectTargetType tries to determine the type of target
func detectTargetType(target string) string {
	switch {
	case strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://"):
		return "url"
	case strings.Contains(target, "/") && !strings.Contains(target, "."):
		return "cidr"
	case strings.Count(target, ".") == 3:
		return "ip"
	case strings.Contains(target, "."):
		return "host"
	default:
		return ""
	}
}
