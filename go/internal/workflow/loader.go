// go/internal/workflow/loader.go
package workflow

import (
	"fmt"
	"os"
	"strings"

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

// TargetDef represents a target definition which can be either a simple string
// or a complex dict with type, field, and condition keys
type TargetDef struct {
	// Simple is the string value for simple targets like "url.url" or "target.name"
	Simple string
	// Type is the output type to filter (e.g., "subdomain", "url")
	Type string
	// Field is the field to extract from the output type
	Field string
	// Condition is a Python expression for filtering
	Condition string
}

// IsSimple returns true if this is a simple string target
func (t TargetDef) IsSimple() bool {
	return t.Simple != ""
}

// TaskNode represents a task in the workflow
type TaskNode struct {
	Name       string
	Type       NodeType
	Task       string
	Options    map[string]any
	Targets    []string    // Simple string targets e.g., ["url.url"] (kept for backward compatibility)
	TargetDefs []TargetDef // Full target definitions including complex dict targets
	Condition  string
	Children   []*TaskNode
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
		if strings.HasPrefix(name, "_group") {
			// Parallel group (e.g., "_group/hunt", "_group/probe", "_group/vuln")
			group := &TaskNode{Type: GroupType, Name: name}
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
						targetDef := parseTargetDef(t)
						node.TargetDefs = append(node.TargetDefs, targetDef)
						// Also populate Targets for backward compatibility with simple strings
						if targetDef.IsSimple() {
							node.Targets = append(node.Targets, targetDef.Simple)
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

// parseTargetDef parses a target definition from either a string or a dict
func parseTargetDef(t interface{}) TargetDef {
	// Handle simple string targets like "url.url" or "target.name"
	if s, ok := t.(string); ok {
		return TargetDef{Simple: s}
	}

	// Handle complex dict targets with type, field, and condition keys
	if m, ok := t.(map[string]any); ok {
		def := TargetDef{}
		if typ, ok := m["type"].(string); ok {
			def.Type = typ
		}
		if field, ok := m["field"].(string); ok {
			def.Field = field
		}
		if cond, ok := m["condition"].(string); ok {
			def.Condition = cond
		}
		return def
	}

	return TargetDef{}
}
