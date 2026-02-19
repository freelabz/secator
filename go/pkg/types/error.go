// go/pkg/types/error.go
package types

// Error represents an error message from execution
type Error struct {
	BaseType
	Message string `json:"message"`
}

func (e *Error) Type() string { return "error" }

func (e *Error) ToMap() map[string]any {
	m := e.BaseType.ToMap()
	m["_type"] = "error"
	m["message"] = e.Message
	return m
}

// NewError creates a new Error with the given message
func NewError(msg string) *Error {
	return &Error{Message: msg}
}
