// Package mongodb provides a MongoDB-backed store implementation.
package mongodb

import (
	"context"
	"time"

	"github.com/freelabz/secator/internal/engine"
	"github.com/freelabz/secator/internal/store"
	"github.com/freelabz/secator/pkg/types"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Config holds MongoDB connection settings.
type Config struct {
	URL                    string `yaml:"url"`
	Database               string `yaml:"database"`
	ServerSelectionTimeout int    `yaml:"server_selection_timeout_ms"`
	MaxPoolSize            int    `yaml:"max_pool_size"`
}

// Store implements store.Store using MongoDB as the backend.
type Store struct {
	client    *mongo.Client
	db        *mongo.Database
	tasks     *mongo.Collection
	workflows *mongo.Collection
	scans     *mongo.Collection
	findings  *mongo.Collection
}

// New creates a new MongoDB store with the given configuration.
func New(cfg Config) (*Store, error) {
	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(cfg.ServerSelectionTimeout)*time.Millisecond)
	defer cancel()

	opts := options.Client().
		ApplyURI(cfg.URL).
		SetMaxPoolSize(uint64(cfg.MaxPoolSize))

	client, err := mongo.Connect(ctx, opts)
	if err != nil {
		return nil, err
	}

	if err := client.Ping(ctx, nil); err != nil {
		return nil, err
	}

	db := client.Database(cfg.Database)
	return &Store{
		client:    client,
		db:        db,
		tasks:     db.Collection("tasks"),
		workflows: db.Collection("workflows"),
		scans:     db.Collection("scans"),
		findings:  db.Collection("findings"),
	}, nil
}

// Name returns the store identifier.
func (s *Store) Name() string { return "mongodb" }

// SaveFinding persists a finding to the findings collection.
// If a document with the same UUID exists, it will be replaced.
func (s *Store) SaveFinding(ctx context.Context, f types.OutputType) error {
	doc := f.ToMap()
	doc["_id"] = f.UUID()
	_, err := s.findings.InsertOne(ctx, doc)
	if mongo.IsDuplicateKeyError(err) {
		_, err = s.findings.ReplaceOne(ctx, bson.M{"_id": f.UUID()}, doc)
	}
	return err
}

// UpdateFinding updates an existing finding by ID.
func (s *Store) UpdateFinding(ctx context.Context, id string, f types.OutputType) error {
	_, err := s.findings.ReplaceOne(ctx, bson.M{"_id": id}, f.ToMap())
	return err
}

// SaveRunner persists a runner state to the appropriate collection based on type.
func (s *Store) SaveRunner(ctx context.Context, r *engine.RunnerState) error {
	coll := s.collectionForType(r.Type)
	_, err := coll.InsertOne(ctx, r)
	return err
}

// UpdateRunner updates an existing runner state by ID.
func (s *Store) UpdateRunner(ctx context.Context, id string, r *engine.RunnerState) error {
	coll := s.collectionForType(r.Type)
	_, err := coll.ReplaceOne(ctx, bson.M{"_id": id}, r)
	return err
}

// collectionForType returns the appropriate collection for a runner type.
func (s *Store) collectionForType(runnerType string) *mongo.Collection {
	switch runnerType {
	case "workflow":
		return s.workflows
	case "scan":
		return s.scans
	default:
		return s.tasks
	}
}

// FindDuplicates finds duplicate findings in a workspace using MongoDB aggregation.
func (s *Store) FindDuplicates(ctx context.Context, workspace string) ([]store.Duplicate, error) {
	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.M{"_context.workspace": workspace}}},
		{{Key: "$group", Value: bson.M{
			"_id":   "$_hash",
			"ids":   bson.M{"$push": "$_id"},
			"count": bson.M{"$sum": 1},
		}}},
		{{Key: "$match", Value: bson.M{"count": bson.M{"$gt": 1}}}},
	}

	cursor, err := s.findings.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var results []store.Duplicate
	for cursor.Next(ctx) {
		var doc struct {
			IDs []string `bson:"ids"`
		}
		if err := cursor.Decode(&doc); err != nil {
			continue
		}
		if len(doc.IDs) > 1 {
			results = append(results, store.Duplicate{
				MainID:     doc.IDs[0],
				RelatedIDs: doc.IDs[1:],
			})
		}
	}
	return results, nil
}

// Close disconnects from MongoDB.
func (s *Store) Close() error {
	return s.client.Disconnect(context.Background())
}
