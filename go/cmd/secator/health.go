// go/cmd/secator/health.go
package main

import (
	"fmt"
	"os/exec"

	"github.com/freelabz/secator/internal/tasks"
	"github.com/spf13/cobra"
)

var healthCmd = &cobra.Command{
	Use:   "health",
	Short: "Check installed tools",
	Run:   runHealth,
}

func init() {
	rootCmd.AddCommand(healthCmd)
}

func runHealth(cmd *cobra.Command, args []string) {
	fmt.Println("Checking installed tools...")
	fmt.Println()

	for _, name := range tasks.Names() {
		task, _ := tasks.Get(name)
		cmdName := task.Command()

		_, err := exec.LookPath(cmdName)
		if err != nil {
			fmt.Printf("  [✗] %s - not found\n", name)
		} else {
			fmt.Printf("  [✓] %s\n", name)
		}
	}
}
