// go/cmd/secator/main.go
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Version is the current version of secator
const Version = "0.1.0-go"

var rootCmd = &cobra.Command{
	Use:   "secator",
	Short: "The Pentester's Swiss Knife",
	Long:  "A security assessment automation tool written in Go",
}

func init() {
	rootCmd.PersistentFlags().StringP("output", "o", "", "Output format (json, csv)")
	rootCmd.PersistentFlags().StringP("profile", "p", "", "Profile (aggressive, stealth)")
	rootCmd.PersistentFlags().Bool("json", false, "JSON output")
	rootCmd.PersistentFlags().StringSlice("store", nil, "Stores to use (mongodb, gcs, api)")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
