// go/pkg/types/types_test.go
package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBaseType_ImplementsOutputType(t *testing.T) {
	var _ OutputType = &BaseType{}
}

func TestBaseType_Type(t *testing.T) {
	b := &BaseType{TypeName: "url"}
	assert.Equal(t, "url", b.Type())
}

func TestBaseType_UUID(t *testing.T) {
	b := &BaseType{}
	uuid := b.UUID()
	assert.NotEmpty(t, uuid)
	// UUID should be consistent
	assert.Equal(t, uuid, b.UUID())
}

func TestBaseType_ToMap(t *testing.T) {
	b := &BaseType{
		TypeName:   "url",
		SourceName: "httpx",
	}
	m := b.ToMap()
	assert.Equal(t, "url", m["_type"])
	assert.Equal(t, "httpx", m["_source"])
	assert.NotEmpty(t, m["_uuid"])
	assert.NotEmpty(t, m["_timestamp"])
}

func TestBaseType_SetContext(t *testing.T) {
	b := &BaseType{}
	ctx := map[string]any{"workspace": "test"}
	b.SetContext(ctx)
	assert.Equal(t, "test", b.Context["workspace"])
}
