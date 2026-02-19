// go/cmd/secator/workflow.go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/freelabz/secator/internal/workflow"
	"github.com/spf13/cobra"
)

var workflowCmd = &cobra.Command{
	Use:     "w [workflow] [targets...]",
	Aliases: []string{"workflow"},
	Short:   "Run a workflow",
	Args:    cobra.MinimumNArgs(2),
	Run:     runWorkflow,
}

func init() {
	workflowCmd.Flags().BoolP("json", "j", false, "Output results as JSON")
	rootCmd.AddCommand(workflowCmd)
}

func runWorkflow(cmd *cobra.Command, args []string) {
	workflowName := args[0]
	targets := args[1:]

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// Try to find workflow file
	paths := []string{
		workflowName,
		workflowName + ".yaml",
		filepath.Join("configs", "workflows", workflowName+".yaml"),
	}

	var wf *workflow.Workflow
	var err error
	for _, p := range paths {
		wf, err = workflow.Load(p)
		if err == nil {
			break
		}
	}

	if wf == nil {
		fmt.Fprintf(os.Stderr, "Workflow not found: %s\n", workflowName)
		os.Exit(1)
	}

	jsonOutput, _ := cmd.Flags().GetBool("json")

	for result := range wf.Run(ctx, targets) {
		if jsonOutput {
			data, err := json.Marshal(result.ToMap())
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error marshaling result: %v\n", err)
				continue
			}
			fmt.Println(string(data))
		} else {
			fmt.Printf("[%s] %v\n", result.Type(), result.ToMap())
		}
	}
}
