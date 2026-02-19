// go/internal/store/store.go
package store

import (
	"context"

	"github.com/freelabz/secator/internal/engine"
	"github.com/freelabz/secator/pkg/types"
)

// Duplicate represents a set of duplicate findings
type Duplicate struct {
	MainID     string
	RelatedIDs []string
}

// Store persists findings and runner state
type Store interface {
	Name() string
	SaveRunner(ctx context.Context, r *engine.RunnerState) error
	UpdateRunner(ctx context.Context, id string, r *engine.RunnerState) error
	SaveFinding(ctx context.Context, f types.OutputType) error
	UpdateFinding(ctx context.Context, id string, f types.OutputType) error
	FindDuplicates(ctx context.Context, workspace string) ([]Duplicate, error)
	Close() error
}

// MultiStore wraps multiple stores
type MultiStore struct {
	stores []Store
}

// NewMultiStore creates a store that writes to multiple backends
func NewMultiStore(stores ...Store) *MultiStore {
	return &MultiStore{stores: stores}
}

func (m *MultiStore) Name() string { return "multi" }

func (m *MultiStore) SaveRunner(ctx context.Context, r *engine.RunnerState) error {
	for _, s := range m.stores {
		if err := s.SaveRunner(ctx, r); err != nil {
			return err
		}
	}
	return nil
}

func (m *MultiStore) UpdateRunner(ctx context.Context, id string, r *engine.RunnerState) error {
	for _, s := range m.stores {
		if err := s.UpdateRunner(ctx, id, r); err != nil {
			return err
		}
	}
	return nil
}

func (m *MultiStore) SaveFinding(ctx context.Context, f types.OutputType) error {
	for _, s := range m.stores {
		if err := s.SaveFinding(ctx, f); err != nil {
			return err
		}
	}
	return nil
}

func (m *MultiStore) UpdateFinding(ctx context.Context, id string, f types.OutputType) error {
	for _, s := range m.stores {
		if err := s.UpdateFinding(ctx, id, f); err != nil {
			return err
		}
	}
	return nil
}

func (m *MultiStore) FindDuplicates(ctx context.Context, workspace string) ([]Duplicate, error) {
	for _, s := range m.stores {
		dups, err := s.FindDuplicates(ctx, workspace)
		if err == nil && len(dups) > 0 {
			return dups, nil
		}
	}
	return nil, nil
}

func (m *MultiStore) Close() error {
	for _, s := range m.stores {
		s.Close()
	}
	return nil
}
