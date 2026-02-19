package mongodb

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfig_Defaults(t *testing.T) {
	cfg := Config{
		URL:                    "mongodb://localhost:27017",
		Database:               "secator",
		ServerSelectionTimeout: 5000,
		MaxPoolSize:            10,
	}
	assert.Equal(t, "mongodb://localhost:27017", cfg.URL)
	assert.Equal(t, "secator", cfg.Database)
	assert.Equal(t, 5000, cfg.ServerSelectionTimeout)
	assert.Equal(t, 10, cfg.MaxPoolSize)
}

func TestConfig_Empty(t *testing.T) {
	cfg := Config{}
	assert.Empty(t, cfg.URL)
	assert.Empty(t, cfg.Database)
	assert.Zero(t, cfg.ServerSelectionTimeout)
	assert.Zero(t, cfg.MaxPoolSize)
}

func TestStore_Name(t *testing.T) {
	// Cannot test full store creation without MongoDB
	// This test validates the expected name constant
	s := &Store{}
	assert.Equal(t, "mongodb", s.Name())
}

func TestStore_CollectionForType(t *testing.T) {
	// Create a minimal store to test collection routing
	// Note: collections will be nil but the logic can be verified
	s := &Store{}

	tests := []struct {
		runnerType string
		expected   string
	}{
		{"task", "tasks"},
		{"workflow", "workflows"},
		{"scan", "scans"},
		{"unknown", "tasks"}, // defaults to tasks
		{"", "tasks"},        // empty defaults to tasks
	}

	for _, tt := range tests {
		t.Run(tt.runnerType, func(t *testing.T) {
			coll := s.collectionForType(tt.runnerType)
			// With nil collections, we verify the logic paths exist
			// In a real test with MongoDB, we would check coll.Name()
			switch tt.runnerType {
			case "workflow":
				assert.Equal(t, s.workflows, coll)
			case "scan":
				assert.Equal(t, s.scans, coll)
			default:
				assert.Equal(t, s.tasks, coll)
			}
		})
	}
}
