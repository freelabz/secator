// go/pkg/types/types.go
package types

import (
	"time"

	"github.com/google/uuid"
)

// OutputType is the base interface all findings implement
type OutputType interface {
	Type() string
	UUID() string
	Source() string
	Timestamp() time.Time
	ToMap() map[string]any
	SetContext(ctx map[string]any)
	String() string // Console representation
}

// BaseType provides common fields for all output types
type BaseType struct {
	TypeName   string         `json:"_type"`
	IDValue    string         `json:"_uuid"`
	SourceName string         `json:"_source"`
	Time       time.Time      `json:"_timestamp"`
	Context    map[string]any `json:"_context,omitempty"`
	Duplicate  bool           `json:"_duplicate,omitempty"`
}

func (b *BaseType) Type() string {
	return b.TypeName
}

func (b *BaseType) UUID() string {
	if b.IDValue == "" {
		b.IDValue = uuid.New().String()
	}
	return b.IDValue
}

func (b *BaseType) Source() string {
	return b.SourceName
}

func (b *BaseType) Timestamp() time.Time {
	if b.Time.IsZero() {
		b.Time = time.Now()
	}
	return b.Time
}

func (b *BaseType) ToMap() map[string]any {
	return map[string]any{
		"_type":      b.Type(),
		"_uuid":      b.UUID(),
		"_source":    b.Source(),
		"_timestamp": b.Timestamp(),
		"_context":   b.Context,
		"_duplicate": b.Duplicate,
	}
}

func (b *BaseType) SetContext(ctx map[string]any) {
	if b.Context == nil {
		b.Context = make(map[string]any)
	}
	for k, v := range ctx {
		b.Context[k] = v
	}
}

// SetSource sets the source name
func (b *BaseType) SetSource(source string) {
	b.SourceName = source
}

// String returns a basic string representation
func (b *BaseType) String() string {
	return b.TypeName
}
