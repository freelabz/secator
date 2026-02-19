// Package gcs provides a Google Cloud Storage-backed store implementation.
// This store is primarily used for uploading files (screenshots, responses)
// referenced in findings to GCS buckets.
package gcs

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"cloud.google.com/go/storage"
	"github.com/freelabz/secator/internal/engine"
	"github.com/freelabz/secator/internal/store"
	"github.com/freelabz/secator/pkg/types"
)

// Config holds GCS configuration settings.
type Config struct {
	BucketName string `yaml:"bucket_name"`
}

// Store implements store.Store using GCS for file uploads.
type Store struct {
	client *storage.Client
	bucket *storage.BucketHandle
	config Config
}

// New creates a new GCS store with the given configuration.
// Uses Application Default Credentials for authentication.
func New(cfg Config) (*Store, error) {
	ctx := context.Background()
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, err
	}
	return &Store{
		client: client,
		bucket: client.Bucket(cfg.BucketName),
		config: cfg,
	}, nil
}

// Name returns the store identifier.
func (s *Store) Name() string { return "gcs" }

// SaveFinding uploads any file attachments referenced in the finding to GCS.
// Supported fields: screenshot_path, stored_response_path
func (s *Store) SaveFinding(ctx context.Context, f types.OutputType) error {
	m := f.ToMap()
	fileFields := []string{"screenshot_path", "stored_response_path"}
	for _, field := range fileFields {
		if path, ok := m[field].(string); ok && path != "" {
			if _, err := os.Stat(path); err == nil {
				_, err := s.upload(ctx, path)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// upload copies a local file to GCS and returns the gs:// URI.
func (s *Store) upload(ctx context.Context, localPath string) (string, error) {
	filename := filepath.Base(localPath)
	blobName := fmt.Sprintf("findings/%s/%s", time.Now().Format("2006-01-02"), filename)
	obj := s.bucket.Object(blobName)
	w := obj.NewWriter(ctx)
	f, err := os.Open(localPath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := io.Copy(w, f); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	return fmt.Sprintf("gs://%s/%s", s.config.BucketName, blobName), nil
}

// SaveRunner is a no-op for GCS store (not applicable for file storage).
func (s *Store) SaveRunner(ctx context.Context, r *engine.RunnerState) error {
	return nil
}

// UpdateRunner is a no-op for GCS store (not applicable for file storage).
func (s *Store) UpdateRunner(ctx context.Context, id string, r *engine.RunnerState) error {
	return nil
}

// UpdateFinding is a no-op for GCS store (files are immutable once uploaded).
func (s *Store) UpdateFinding(ctx context.Context, id string, f types.OutputType) error {
	return nil
}

// FindDuplicates is not supported by GCS store.
func (s *Store) FindDuplicates(ctx context.Context, workspace string) ([]store.Duplicate, error) {
	return nil, nil
}

// Close releases the GCS client resources.
func (s *Store) Close() error {
	return s.client.Close()
}
