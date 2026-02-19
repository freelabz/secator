// Package api provides an HTTP API-backed store implementation.
// This store syncs findings and runner state to a remote API endpoint.
package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/freelabz/secator/internal/engine"
	"github.com/freelabz/secator/internal/store"
	"github.com/freelabz/secator/pkg/types"
)

// Endpoints configures the API endpoint paths.
type Endpoints struct {
	RunnerCreate  string `yaml:"runner_create"`
	RunnerUpdate  string `yaml:"runner_update"`
	FindingCreate string `yaml:"finding_create"`
	FindingUpdate string `yaml:"finding_update"`
}

// Config holds API connection settings.
type Config struct {
	URL        string    `yaml:"url"`
	Key        string    `yaml:"key"`
	HeaderName string    `yaml:"header_name"`
	ForceSSL   bool      `yaml:"force_ssl"`
	Endpoints  Endpoints `yaml:"endpoints"`
}

// Store implements store.Store using HTTP API calls.
type Store struct {
	baseURL    string
	apiKey     string
	headerName string
	client     *http.Client
	endpoints  Endpoints
}

// New creates a new API store with the given configuration.
func New(cfg Config) (*Store, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !cfg.ForceSSL},
	}
	return &Store{
		baseURL:    cfg.URL,
		apiKey:     cfg.Key,
		headerName: cfg.HeaderName,
		client:     &http.Client{Transport: transport, Timeout: 30 * time.Second},
		endpoints:  cfg.Endpoints,
	}, nil
}

// Name returns the store identifier.
func (s *Store) Name() string { return "api" }

// SaveFinding sends a finding to the API's finding create endpoint.
func (s *Store) SaveFinding(ctx context.Context, f types.OutputType) error {
	url := s.baseURL + s.endpoints.FindingCreate
	return s.post(ctx, url, f.ToMap())
}

// UpdateFinding sends an update to the API's finding update endpoint.
func (s *Store) UpdateFinding(ctx context.Context, id string, f types.OutputType) error {
	url := s.baseURL + strings.Replace(s.endpoints.FindingUpdate, "{finding_id}", id, 1)
	return s.put(ctx, url, f.ToMap())
}

// SaveRunner sends a runner state to the API's runner create endpoint.
func (s *Store) SaveRunner(ctx context.Context, r *engine.RunnerState) error {
	url := s.baseURL + s.endpoints.RunnerCreate
	return s.post(ctx, url, r)
}

// UpdateRunner sends an update to the API's runner update endpoint.
func (s *Store) UpdateRunner(ctx context.Context, id string, r *engine.RunnerState) error {
	url := s.baseURL + strings.Replace(s.endpoints.RunnerUpdate, "{runner_id}", id, 1)
	return s.put(ctx, url, r)
}

// FindDuplicates is not supported by API store (handled server-side).
func (s *Store) FindDuplicates(ctx context.Context, workspace string) ([]store.Duplicate, error) {
	return nil, nil
}

// Close is a no-op for API store.
func (s *Store) Close() error {
	return nil
}

// post sends a POST request to the given URL with JSON body.
func (s *Store) post(ctx context.Context, url string, body any) error {
	return s.request(ctx, "POST", url, body)
}

// put sends a PUT request to the given URL with JSON body.
func (s *Store) put(ctx context.Context, url string, body any) error {
	return s.request(ctx, "PUT", url, body)
}

// request performs an HTTP request with JSON body and authentication.
func (s *Store) request(ctx context.Context, method, url string, body any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.apiKey != "" {
		req.Header.Set(s.headerName, s.apiKey)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error %d: %s", resp.StatusCode, body)
	}
	return nil
}
