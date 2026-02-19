// go/internal/workflow/loader.go
package workflow

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents the YAML workflow structure
type Config struct {
	Type        string                 `yaml:"type"`
	Name        string                 `yaml:"name"`
	Description string                 `yaml:"description"`
	InputTypes  []string               `yaml:"input_types"`
	Options     map[string]OptionDef   `yaml:"options"`
	Tasks       map[string]interface{} `yaml:"tasks"`
}

// OptionDef defines a workflow option
type OptionDef struct {
	IsFlag  bool        `yaml:"is_flag"`
	Default interface{} `yaml:"default"`
	Help    string      `yaml:"help"`
}

// TaskNode represents a task in the workflow
type TaskNode struct {
	Name      string
	Type      NodeType
	Task      string
	Options   map[string]any
	Targets   []string // e.g., ["url.url"]
	Condition string
	Children  []*TaskNode
}

// NodeType distinguishes task types
type NodeType int

const (
	TaskType NodeType = iota
	GroupType
	ChainType
)

// Workflow represents a loaded workflow
type Workflow struct {
	config Config
	root   *TaskNode
}

// Load parses a workflow YAML file
func Load(path string) (*Workflow, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	if cfg.Type != "workflow" {
		return nil, fmt.Errorf("expected type 'workflow', got '%s'", cfg.Type)
	}

	root := parseTaskTree(cfg.Tasks)
	return &Workflow{config: cfg, root: root}, nil
}

// Name returns the workflow name
func (w *Workflow) Name() string {
	return w.config.Name
}

// TaskNames returns all task names in the workflow
func (w *Workflow) TaskNames() []string {
	var names []string
	collectTaskNames(w.root, &names)
	return names
}

func collectTaskNames(node *TaskNode, names *[]string) {
	if node == nil {
		return
	}
	if node.Type == TaskType && node.Task != "" {
		*names = append(*names, node.Task)
	}
	for _, child := range node.Children {
		collectTaskNames(child, names)
	}
}

func parseTaskTree(tasks map[string]interface{}) *TaskNode {
	root := &TaskNode{Type: ChainType}

	for name, spec := range tasks {
		if name == "_group" {
			// Parallel group
			group := &TaskNode{Type: GroupType}
			if groupTasks, ok := spec.(map[string]any); ok {
				for childName, childSpec := range groupTasks {
					group.Children = append(group.Children, parseTaskNode(childName, childSpec))
				}
			}
			root.Children = append(root.Children, group)
		} else {
			// Sequential task
			root.Children = append(root.Children, parseTaskNode(name, spec))
		}
	}

	return root
}

func parseTaskNode(name string, spec interface{}) *TaskNode {
	node := &TaskNode{
		Type:    TaskType,
		Name:    name,
		Task:    name,
		Options: make(map[string]any),
	}

	if opts, ok := spec.(map[string]any); ok {
		for k, v := range opts {
			if k == "targets_" {
				if targets, ok := v.([]any); ok {
					for _, t := range targets {
						if s, ok := t.(string); ok {
							node.Targets = append(node.Targets, s)
						}
					}
				}
			} else if k == "if" {
				if cond, ok := v.(string); ok {
					node.Condition = cond
				}
			} else {
				node.Options[k] = v
			}
		}
	}

	return node
}
