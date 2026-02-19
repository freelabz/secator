// go/internal/tasks/registry.go
package tasks

import (
	"github.com/freelabz/secator/internal/engine"
)

// TaskFactory creates a new task instance
type TaskFactory func() engine.Task

var registry = make(map[string]TaskFactory)

// Register adds a task factory to the registry
func Register(name string, factory TaskFactory) {
	registry[name] = factory
}

// Get retrieves a task by name
func Get(name string) (engine.Task, bool) {
	factory, ok := registry[name]
	if !ok {
		return nil, false
	}
	return factory(), true
}

// All returns all registered task names and factories
func All() map[string]TaskFactory {
	result := make(map[string]TaskFactory)
	for k, v := range registry {
		result[k] = v
	}
	return result
}

// Names returns all registered task names
func Names() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	return names
}
