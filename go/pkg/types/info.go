// go/pkg/types/info.go
package types

import "github.com/freelabz/secator/pkg/console"

// Info represents an informational message from execution
type Info struct {
	BaseType
	Message string `json:"message"`
}

func (i *Info) Type() string { return "info" }

func (i *Info) ToMap() map[string]any {
	m := i.BaseType.ToMap()
	m["_type"] = "info"
	m["message"] = i.Message
	return m
}

// NewInfo creates a new Info with the given message
func NewInfo(msg string) *Info {
	return &Info{Message: msg}
}

// String returns a formatted console representation
func (i *Info) String() string {
	return console.Info(i.Message)
}
