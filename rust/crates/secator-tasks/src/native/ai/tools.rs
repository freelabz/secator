//! OpenAI-format tool schemas — Python parity with
//! `secator/ai/tools.py::TOOL_SCHEMAS`.
//!
//! Each schema declares one of the meta-tools the agent loop exposes to the
//! LLM. The LLM picks a tool name + arguments object; `tool_call_to_action`
//! converts that into a normalized action dict that `dispatch.rs` knows how to
//! run.

use serde_json::{json, Value};

/// The full set of tool schemas, filtered by the mode's `allowed_actions`
/// (Python parity with `build_tool_schemas`). Subagent runs additionally strip
/// `follow_up` since they can't prompt the operator.
pub fn build_tool_schemas(mode: &str, is_subagent: bool) -> Value {
    let cfg = super::prompts::get_mode_config(mode);
    let mut out: Vec<Value> = Vec::new();
    for (name, schema) in all_schemas() {
        if is_subagent && name == "follow_up" {
            continue;
        }
        let action = action_type_for(name);
        if !cfg.allowed_actions.contains(&action) {
            continue;
        }
        out.push(schema);
    }
    Value::Array(out)
}

/// All known tool names. Order mirrors Python `TOOL_SCHEMAS` insertion order.
pub const TOOL_NAMES: &[&str] = &[
    "run_task",
    "run_workflow",
    "run_shell",
    "query_workspace",
    "follow_up",
    "add_finding",
    "stop",
];

/// Convert an LLM tool call (name + arguments object) to a normalized action
/// dict. Returns `None` for unknown tool names. Mirrors Python
/// `tool_call_to_action`.
pub fn tool_call_to_action(name: &str, arguments: &Value) -> Option<Value> {
    if !TOOL_NAMES.contains(&name) {
        return None;
    }
    let mut action = serde_json::Map::new();
    action.insert("action".into(), Value::String(action_type_for(name).into()));
    if let Value::Object(args) = arguments {
        for (k, v) in args {
            if k == "action" || k == "description" {
                continue;
            }
            action.insert(k.clone(), v.clone());
        }
    }
    Some(Value::Object(action))
}

/// Map tool name → action type. Python `TOOL_ACTION_MAP`.
pub fn action_type_for(tool: &str) -> &'static str {
    match tool {
        "run_task" => "task",
        "run_workflow" => "workflow",
        "run_shell" => "shell",
        "query_workspace" => "query",
        "follow_up" => "follow_up",
        "add_finding" => "add_finding",
        "stop" => "stop",
        _ => "",
    }
}

fn all_schemas() -> Vec<(&'static str, Value)> {
    vec![
        ("run_task", run_task_schema()),
        ("run_workflow", run_workflow_schema()),
        ("run_shell", run_shell_schema()),
        ("query_workspace", query_workspace_schema()),
        ("follow_up", follow_up_schema()),
        ("add_finding", add_finding_schema()),
        ("stop", stop_schema()),
    ]
}

fn run_task_schema() -> Value {
    json!({
        "type": "function",
        "function": {
            "name": "run_task",
            "description": "Run a secator security task (e.g. nmap, httpx, nuclei) against one or more targets.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "The task name (e.g. nmap, httpx, nuclei, ffuf)."},
                    "targets": {"type": "array", "items": {"type": "string"}, "description": "List of targets (hosts, URLs, IPs)."},
                    "opts": {"type": "object", "description": "Optional task-specific options (e.g. ports, rate_limit, timeout)."}
                },
                "required": ["name", "targets"]
            }
        }
    })
}

fn run_workflow_schema() -> Value {
    json!({
        "type": "function",
        "function": {
            "name": "run_workflow",
            "description": "Run a secator workflow (a composed sequence of tasks) against one or more targets.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "The workflow name."},
                    "targets": {"type": "array", "items": {"type": "string"}, "description": "List of targets (hosts, URLs, IPs)."},
                    "opts": {"type": "object", "description": "Optional workflow options (e.g. profiles)."}
                },
                "required": ["name", "targets"]
            }
        }
    })
}

fn run_shell_schema() -> Value {
    json!({
        "type": "function",
        "function": {
            "name": "run_shell",
            "description": "Run a shell command for exploration, data analysis, or composing tool output (grep, jq, etc.).",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "The shell command to execute."}
                },
                "required": ["command"]
            }
        }
    })
}

fn query_workspace_schema() -> Value {
    json!({
        "type": "function",
        "function": {
            "name": "query_workspace",
            "description": "Query the workspace database for stored security findings using MongoDB-style queries.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "object", "description": "MongoDB-style query object."},
                    "limit": {"type": "integer", "default": 100}
                },
                "required": ["query"]
            }
        }
    })
}

fn follow_up_schema() -> Value {
    json!({
        "type": "function",
        "function": {
            "name": "follow_up",
            "description": "Ask the user a follow-up question to clarify next steps.",
            "parameters": {
                "type": "object",
                "properties": {
                    "reason": {"type": "string", "description": "Why a follow-up is needed."},
                    "choices": {"type": "array", "items": {"type": "string"}, "description": "Optional concrete action choices."}
                },
                "required": ["reason"]
            }
        }
    })
}

fn add_finding_schema() -> Value {
    json!({
        "type": "function",
        "function": {
            "name": "add_finding",
            "description": "Add a security finding to the workspace (vulnerability, exploit, url, ...).",
            "parameters": {
                "type": "object",
                "properties": {
                    "_type": {"type": "string", "description": "The finding type (vulnerability, exploit, url, port, ...)."}
                },
                "required": ["_type"],
                "additionalProperties": true
            }
        }
    })
}

fn stop_schema() -> Value {
    json!({
        "type": "function",
        "function": {
            "name": "stop",
            "description": "Stop the current session. Call when the user request has been fulfilled or when you cannot proceed without user input.",
            "parameters": {
                "type": "object",
                "properties": {
                    "reason": {"type": "string", "description": "Why you are stopping (summary or blocker description)."}
                },
                "required": ["reason"]
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schema_names(v: &Value) -> Vec<&str> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|s| s["function"]["name"].as_str().unwrap())
            .collect()
    }

    #[test]
    fn attack_mode_includes_all_tools() {
        let v = build_tool_schemas("attack", false);
        let names = schema_names(&v);
        assert_eq!(names.len(), TOOL_NAMES.len(), "attack should include every tool");
        for t in TOOL_NAMES {
            assert!(names.contains(t), "missing tool {t}");
        }
    }

    #[test]
    fn subagent_strips_follow_up() {
        let v = build_tool_schemas("attack", true);
        let names = schema_names(&v);
        assert!(!names.contains(&"follow_up"));
        assert!(names.contains(&"run_task"));
    }

    /// #174 T5: chat mode strips `run_task`, `run_workflow`, and the LLM
    /// literally never sees their schemas. Python parity.
    #[test]
    fn chat_mode_strips_run_task_and_run_workflow() {
        let v = build_tool_schemas("chat", false);
        let names = schema_names(&v);
        assert!(!names.contains(&"run_task"), "chat must not expose run_task");
        assert!(!names.contains(&"run_workflow"), "chat must not expose run_workflow");
        // Still has the read-only / interactive bits.
        assert!(names.contains(&"query_workspace"));
        assert!(names.contains(&"follow_up"));
        assert!(names.contains(&"add_finding"));
        assert!(names.contains(&"stop"));
        assert!(names.contains(&"run_shell"));
    }

    /// #174 T5: exploit mode drops `query_workspace` + `follow_up` — Python parity.
    #[test]
    fn exploit_mode_drops_query_and_follow_up() {
        let v = build_tool_schemas("exploit", false);
        let names = schema_names(&v);
        assert!(!names.contains(&"query_workspace"));
        assert!(!names.contains(&"follow_up"));
        assert!(names.contains(&"run_task"));
        assert!(names.contains(&"run_workflow"));
        assert!(names.contains(&"add_finding"));
    }

    #[test]
    fn tool_call_to_action_maps_known_tools() {
        let args = json!({"name":"nmap","targets":["example.com"],"opts":{"ports":"80,443"}});
        let action = tool_call_to_action("run_task", &args).unwrap();
        assert_eq!(action["action"], "task");
        assert_eq!(action["name"], "nmap");
        assert_eq!(action["targets"][0], "example.com");
        assert_eq!(action["opts"]["ports"], "80,443");
    }

    #[test]
    fn tool_call_to_action_strips_action_and_description_fields() {
        // Defensive: don't let the LLM hijack our action discriminator.
        let args = json!({"name":"x","targets":[],"action":"hijack","description":"foo"});
        let action = tool_call_to_action("run_task", &args).unwrap();
        assert_eq!(action["action"], "task"); // ours, not theirs
        assert!(!action.as_object().unwrap().contains_key("description"));
    }

    #[test]
    fn unknown_tool_returns_none() {
        assert!(tool_call_to_action("does_not_exist", &json!({})).is_none());
    }
}
