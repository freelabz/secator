// go/internal/broker/machinery/machinery.go
package machinery

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/RichardKnop/machinery/v2"
	backendsiface "github.com/RichardKnop/machinery/v2/backends/iface"
	backendsredis "github.com/RichardKnop/machinery/v2/backends/redis"
	brokersiface "github.com/RichardKnop/machinery/v2/brokers/iface"
	brokersredis "github.com/RichardKnop/machinery/v2/brokers/redis"
	"github.com/RichardKnop/machinery/v2/config"
	lockseager "github.com/RichardKnop/machinery/v2/locks/eager"
	locksiface "github.com/RichardKnop/machinery/v2/locks/iface"
	"github.com/RichardKnop/machinery/v2/tasks"
	"github.com/freelabz/secator/internal/broker"
	"github.com/freelabz/secator/pkg/types"
)

// Config for Machinery
type Config struct {
	BrokerURL     string `yaml:"broker_url"`     // redis://localhost:6379
	ResultBackend string `yaml:"result_backend"` // redis://localhost:6379
	DefaultQueue  string `yaml:"default_queue"`
	ResultsTTL    int    `yaml:"results_ttl"`
}

// Broker implements broker.Broker using Machinery
type Broker struct {
	server   *machinery.Server
	handlers map[string]broker.TaskHandler
}

// parseRedisURL parses a Redis URL and returns host, password, and db
func parseRedisURL(redisURL string) (host, username, password string, db int, err error) {
	u, err := url.Parse(redisURL)
	if err != nil {
		return "", "", "", 0, err
	}

	host = u.Host
	if u.User != nil {
		username = u.User.Username()
		password, _ = u.User.Password()
	}

	// Parse db from path (e.g., /0)
	db = 0
	if u.Path != "" && u.Path != "/" {
		dbStr := strings.TrimPrefix(u.Path, "/")
		if dbStr != "" {
			db, err = strconv.Atoi(dbStr)
			if err != nil {
				return "", "", "", 0, fmt.Errorf("invalid db number in URL: %w", err)
			}
		}
	}

	return host, username, password, db, nil
}

// New creates a new Machinery broker
func New(cfg Config) (*Broker, error) {
	mcfg := &config.Config{
		Broker:          cfg.BrokerURL,
		DefaultQueue:    cfg.DefaultQueue,
		ResultBackend:   cfg.ResultBackend,
		ResultsExpireIn: cfg.ResultsTTL,
	}

	// Parse broker URL to create Redis broker
	brokerHost, brokerUser, brokerPass, brokerDB, err := parseRedisURL(cfg.BrokerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse broker URL: %w", err)
	}

	// Parse backend URL to create Redis backend
	backendHost, backendUser, backendPass, backendDB, err := parseRedisURL(cfg.ResultBackend)
	if err != nil {
		return nil, fmt.Errorf("failed to parse backend URL: %w", err)
	}

	var redisBroker brokersiface.Broker = brokersredis.New(mcfg, brokerHost, brokerUser, brokerPass, "", brokerDB)
	var redisBackend backendsiface.Backend = backendsredis.New(mcfg, backendHost, backendUser, backendPass, "", backendDB)
	var eagerLock locksiface.Lock = lockseager.New()

	server := machinery.NewServer(mcfg, redisBroker, redisBackend, eagerLock)

	return &Broker{
		server:   server,
		handlers: make(map[string]broker.TaskHandler),
	}, nil
}

// RegisterTask registers a task handler
func (b *Broker) RegisterTask(name string, handler broker.TaskHandler) error {
	b.handlers[name] = handler

	return b.server.RegisterTask(name, func(inputsJSON, optsJSON string) (string, error) {
		var inputs []string
		var opts map[string]any

		if err := json.Unmarshal([]byte(inputsJSON), &inputs); err != nil {
			return "", fmt.Errorf("failed to unmarshal inputs: %w", err)
		}
		if err := json.Unmarshal([]byte(optsJSON), &opts); err != nil {
			return "", fmt.Errorf("failed to unmarshal opts: %w", err)
		}

		ctx := context.Background()
		results, err := handler(ctx, inputs, opts)
		if err != nil {
			return "", err
		}

		// Serialize results
		var output []map[string]any
		for _, r := range results {
			output = append(output, r.ToMap())
		}

		data, err := json.Marshal(output)
		if err != nil {
			return "", fmt.Errorf("failed to marshal results: %w", err)
		}
		return string(data), nil
	})
}

// Enqueue submits a task for execution
func (b *Broker) Enqueue(ctx context.Context, task string, inputs []string, opts map[string]any) (broker.JobID, error) {
	inputsJSON, err := json.Marshal(inputs)
	if err != nil {
		return "", fmt.Errorf("failed to marshal inputs: %w", err)
	}
	optsJSON, err := json.Marshal(opts)
	if err != nil {
		return "", fmt.Errorf("failed to marshal opts: %w", err)
	}

	sig := &tasks.Signature{
		Name: task,
		Args: []tasks.Arg{
			{Type: "string", Value: string(inputsJSON)},
			{Type: "string", Value: string(optsJSON)},
		},
	}

	result, err := b.server.SendTask(sig)
	if err != nil {
		return "", err
	}

	return broker.JobID(result.GetState().TaskUUID), nil
}

// EnqueueWorkflow submits a workflow for execution
func (b *Broker) EnqueueWorkflow(ctx context.Context, spec broker.WorkflowSpec) (broker.JobID, error) {
	var sigs []*tasks.Signature

	for _, node := range spec.Nodes {
		sig := &tasks.Signature{
			Name: node.TaskName,
			Args: []tasks.Arg{
				{Type: "string", Value: mustJSON(node.Inputs)},
				{Type: "string", Value: node.OptsJSON},
			},
		}
		sigs = append(sigs, sig)
	}

	if len(sigs) == 0 {
		return "", fmt.Errorf("workflow has no tasks")
	}

	chain, err := tasks.NewChain(sigs...)
	if err != nil {
		return "", err
	}

	_, err = b.server.SendChain(chain)
	if err != nil {
		return "", err
	}

	// For chains, the first task's UUID is set after SendChain
	// We use the first signature's UUID as the chain identifier
	return broker.JobID(chain.Tasks[0].UUID), nil
}

// Results returns results for a job (blocking)
func (b *Broker) Results(ctx context.Context, jobID broker.JobID) (<-chan types.OutputType, error) {
	out := make(chan types.OutputType)

	go func() {
		defer close(out)
		// Implementation would poll for results
		// For now, just close the channel
	}()

	return out, nil
}

// Status returns the status of a job
func (b *Broker) Status(ctx context.Context, jobID broker.JobID) (broker.JobStatus, error) {
	// Implementation would check job state
	return broker.JobPending, nil
}

// StartWorker starts a worker
func (b *Broker) StartWorker(ctx context.Context, concurrency int) error {
	worker := b.server.NewWorker("secator-worker", concurrency)

	errCh := make(chan error)
	go func() {
		errCh <- worker.Launch()
	}()

	select {
	case <-ctx.Done():
		worker.Quit()
		return nil
	case err := <-errCh:
		return err
	}
}

// Close closes the broker
func (b *Broker) Close() error {
	return nil
}

func mustJSON(v any) string {
	data, _ := json.Marshal(v)
	return string(data)
}

// Compile-time check that Broker implements broker.Broker
var _ broker.Broker = (*Broker)(nil)
