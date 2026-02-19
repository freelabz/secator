// go/cmd/secator/task.go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"

	"github.com/freelabz/secator/internal/tasks"
	_ "github.com/freelabz/secator/internal/tasks/httpx"
	_ "github.com/freelabz/secator/internal/tasks/nuclei"
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
		fmt.Fprintf(os.Stderr, "Unknown task: %s\n", taskName)
		fmt.Fprintf(os.Stderr, "Available tasks: %v\n", tasks.Names())
		os.Exit(1)
	}

	jsonOutput, _ := cmd.Flags().GetBool("json")

	for result := range task.Run(ctx, targets) {
		if jsonOutput {
			data, _ := json.Marshal(result.ToMap())
			fmt.Println(string(data))
		} else {
			fmt.Printf("[%s] %v\n", result.Type(), result.ToMap())
		}
	}
}
