// go/cmd/secator/worker.go
package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var workerCmd = &cobra.Command{
	Use:   "worker",
	Short: "Start a worker",
	Run:   runWorker,
}

func init() {
	workerCmd.Flags().IntP("concurrency", "c", 0, "Worker concurrency")
	rootCmd.AddCommand(workerCmd)
}

func runWorker(cmd *cobra.Command, args []string) {
	fmt.Println("Worker mode not yet implemented")
}
