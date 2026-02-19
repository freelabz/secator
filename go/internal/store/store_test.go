// go/internal/store/store_test.go
package store

import (
	"context"
	"testing"

	"github.com/freelabz/secator/internal/engine"
	"github.com/freelabz/secator/pkg/types"
	"github.com/stretchr/testify/assert"
)

type mockStore struct {
	name     string
	findings []types.OutputType
	runners  []*engine.RunnerState
}

func (m *mockStore) Name() string { return m.name }
func (m *mockStore) SaveRunner(ctx context.Context, r *engine.RunnerState) error {
	m.runners = append(m.runners, r)
	return nil
}
func (m *mockStore) UpdateRunner(ctx context.Context, id string, r *engine.RunnerState) error {
	return nil
}
func (m *mockStore) SaveFinding(ctx context.Context, f types.OutputType) error {
	m.findings = append(m.findings, f)
	return nil
}
func (m *mockStore) UpdateFinding(ctx context.Context, id string, f types.OutputType) error {
	return nil
}
func (m *mockStore) FindDuplicates(ctx context.Context, workspace string) ([]Duplicate, error) {
	return nil, nil
}
func (m *mockStore) Close() error { return nil }

func TestMultiStore_SaveFinding(t *testing.T) {
	s1 := &mockStore{name: "s1"}
	s2 := &mockStore{name: "s2"}
	multi := NewMultiStore(s1, s2)

	url := &types.URL{URL: "https://example.com"}
	err := multi.SaveFinding(context.Background(), url)

	assert.NoError(t, err)
	assert.Len(t, s1.findings, 1)
	assert.Len(t, s2.findings, 1)
}

func TestMultiStore_Name(t *testing.T) {
	multi := NewMultiStore()
	assert.Equal(t, "multi", multi.Name())
}

func TestMultiStore_SaveRunner(t *testing.T) {
	s1 := &mockStore{name: "s1"}
	s2 := &mockStore{name: "s2"}
	multi := NewMultiStore(s1, s2)

	runner := &engine.RunnerState{
		ID:   "test-runner-1",
		Name: "httpx",
		Type: "task",
	}
	err := multi.SaveRunner(context.Background(), runner)

	assert.NoError(t, err)
	assert.Len(t, s1.runners, 1)
	assert.Len(t, s2.runners, 1)
	assert.Equal(t, "test-runner-1", s1.runners[0].ID)
	assert.Equal(t, "test-runner-1", s2.runners[0].ID)
}

func TestMultiStore_Close(t *testing.T) {
	s1 := &mockStore{name: "s1"}
	s2 := &mockStore{name: "s2"}
	multi := NewMultiStore(s1, s2)

	err := multi.Close()
	assert.NoError(t, err)
}

func TestMultiStore_FindDuplicates(t *testing.T) {
	s1 := &mockStore{name: "s1"}
	multi := NewMultiStore(s1)

	dups, err := multi.FindDuplicates(context.Background(), "test-workspace")
	assert.NoError(t, err)
	assert.Nil(t, dups)
}
