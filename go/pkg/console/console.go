// Package console provides terminal color and formatting utilities
package console

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
)

// Colors for console output
var (
	// Status colors
	Green   = color.New(color.FgGreen).SprintFunc()
	Red     = color.New(color.FgRed).SprintFunc()
	Yellow  = color.New(color.FgYellow).SprintFunc()
	Blue    = color.New(color.FgBlue).SprintFunc()
	Magenta = color.New(color.FgMagenta).SprintFunc()
	Cyan    = color.New(color.FgCyan).SprintFunc()
	White   = color.New(color.FgWhite).SprintFunc()

	// Bold variants
	BoldRed     = color.New(color.FgRed, color.Bold).SprintFunc()
	BoldGreen   = color.New(color.FgGreen, color.Bold).SprintFunc()
	BoldYellow  = color.New(color.FgYellow, color.Bold).SprintFunc()
	BoldMagenta = color.New(color.FgMagenta, color.Bold).SprintFunc()
	BoldWhite   = color.New(color.FgWhite, color.Bold).SprintFunc()

	// Dim
	Dim = color.New(color.Faint).SprintFunc()
)

// SeverityColor returns a color function based on severity level
func SeverityColor(severity string) func(a ...interface{}) string {
	switch strings.ToLower(severity) {
	case "critical":
		return BoldRed
	case "high":
		return Red
	case "medium":
		return Yellow
	case "low":
		return Green
	case "info":
		return Magenta
	default:
		return Dim
	}
}

// StatusCodeColor returns a color function based on HTTP status code
func StatusCodeColor(code int) func(a ...interface{}) string {
	switch {
	case code >= 200 && code < 300:
		return Green
	case code >= 300 && code < 400:
		return Yellow
	case code >= 400:
		return Red
	default:
		return White
	}
}

// Banner returns the secator ASCII banner
func Banner(version string) string {
	banner := `
                         __
   ________  _________ _/ /_____  _____
  / ___/ _ \/ ___/ __ ` + "`" + `/ __/ __ \/ ___/
 (__  /  __/ /__/ /_/ / /_/ /_/ / /
/____/\___/\___/\__,_/\__/\____/_/     %s

                        freelabz.com
`
	return fmt.Sprintf(banner, Cyan("v"+version))
}

// Info prints an info message
func Info(msg string) string {
	return fmt.Sprintf("[%s] %s", Blue("INF"), msg)
}

// Warn prints a warning message
func Warn(msg string) string {
	return fmt.Sprintf("[%s] %s", Yellow("WRN"), msg)
}

// Err prints an error message
func Err(msg string) string {
	return fmt.Sprintf("[%s] %s", BoldRed("ERR"), msg)
}

// Target formats a target with emoji
func Target(name, typ string) string {
	s := fmt.Sprintf("      %s %s", "🎯", name)
	if typ != "" {
		s += fmt.Sprintf(" (%s)", typ)
	}
	return s
}

// TaskStart formats a task start message
func TaskStart(name, description string) string {
	return Info(fmt.Sprintf("Task %s (%s) started", BoldWhite(name), description))
}

// TaskEnd formats a task end message
func TaskEnd(name, status string, count int) string {
	statusColor := Green
	if status != "SUCCESS" {
		statusColor = Red
	}
	return Info(fmt.Sprintf("Task %s finished with status %s and found %d findings",
		name, statusColor(status), count))
}

// Command formats a command line
func Command(cmd string) string {
	return fmt.Sprintf("%s %s", "⚡", Dim(cmd))
}

// TrimString trims a string to max length with ellipsis
func TrimString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// JoinTech joins technology strings with colors
func JoinTech(techs []string) string {
	if len(techs) == 0 {
		return ""
	}
	colored := make([]string, len(techs))
	for i, t := range techs {
		colored[i] = Magenta(t)
	}
	return "[" + strings.Join(colored, ", ") + "]"
}

// JoinTags joins tag strings with colors
func JoinTags(tags []string) string {
	if len(tags) == 0 {
		return ""
	}
	return "[" + Cyan(strings.Join(tags, ",")) + "]"
}
