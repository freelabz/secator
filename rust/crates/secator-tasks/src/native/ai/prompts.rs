//! System prompts — Python parity with `secator/ai/prompts.py`.
//!
//! Loads mode templates (`modes/<mode>.txt`) at compile time via `include_str!`
//! and resolves `${name}` includes against the `constraints/<name>.txt` set.
//! Variable substitution mirrors Python `string.Template.safe_substitute`:
//!   * `$var` and `${var}` get replaced by `vars[var]`,
//!   * unknown placeholders are left as-is.
//!
//! Modes carried over verbatim from Python:
//!   * `attack` — full tool surface, library reference baked in.
//!   * `chat`   — read-only conversational mode (no run_task/run_workflow).
//!   * `exploit` — task/workflow/shell, no follow_up.
//!
//! Library reference (the `<tasks>` / `<workflows>` / `<profiles>` / etc.
//! sections) is built at render time from the live registries so it always
//! reflects the binary's catalogue.

use std::collections::HashMap;
use std::sync::OnceLock;

use regex::Regex;

// ----------------------------------------------------------------- Mode files

const MODE_ATTACK: &str = include_str!("prompts/modes/attack.txt");
const MODE_CHAT: &str = include_str!("prompts/modes/chat.txt");
const MODE_EXPLOIT: &str = include_str!("prompts/modes/exploit.txt");

// --------------------------------------------------------------- Constraints

const CONSTRAINT_ARSENAL: &str = include_str!("prompts/constraints/arsenal.txt");
const CONSTRAINT_COMMON: &str = include_str!("prompts/constraints/common.txt");
const CONSTRAINT_DISCOVERY: &str = include_str!("prompts/constraints/discovery.txt");
const CONSTRAINT_EXPLOITATION_REPORT: &str =
    include_str!("prompts/constraints/exploitation_report.txt");
const CONSTRAINT_FINDINGS: &str = include_str!("prompts/constraints/findings.txt");
const CONSTRAINT_FOLLOW_UP: &str = include_str!("prompts/constraints/follow_up.txt");
const CONSTRAINT_GUARDRAILS: &str = include_str!("prompts/constraints/guardrails.txt");
const CONSTRAINT_ISOLATION: &str = include_str!("prompts/constraints/isolation.txt");
const CONSTRAINT_QUERIES: &str = include_str!("prompts/constraints/queries.txt");
const CONSTRAINT_STOP: &str = include_str!("prompts/constraints/stop.txt");
const CONSTRAINT_SUBAGENT: &str = include_str!("prompts/constraints/subagent.txt");
const CONSTRAINT_SUBAGENTS: &str = include_str!("prompts/constraints/subagents.txt");
const CONSTRAINT_TOOL_RESULT_ANALYSIS: &str =
    include_str!("prompts/constraints/tool_result_analysis.txt");

/// Resolve a `${name}` include token against the bundled `constraints/*.txt`
/// files. Returns `None` when the name doesn't match a known constraint, in
/// which case the include site is left untouched (it might be a `$variable`
/// placeholder for the substitution pass).
fn constraint_body(name: &str) -> Option<&'static str> {
    match name {
        "arsenal" => Some(CONSTRAINT_ARSENAL),
        "common" => Some(CONSTRAINT_COMMON),
        "discovery" => Some(CONSTRAINT_DISCOVERY),
        "exploitation_report" => Some(CONSTRAINT_EXPLOITATION_REPORT),
        "findings" => Some(CONSTRAINT_FINDINGS),
        "follow_up" => Some(CONSTRAINT_FOLLOW_UP),
        "guardrails" => Some(CONSTRAINT_GUARDRAILS),
        "isolation" => Some(CONSTRAINT_ISOLATION),
        "queries" => Some(CONSTRAINT_QUERIES),
        "stop" => Some(CONSTRAINT_STOP),
        "subagent" => Some(CONSTRAINT_SUBAGENT),
        "subagents" => Some(CONSTRAINT_SUBAGENTS),
        "tool_result_analysis" => Some(CONSTRAINT_TOOL_RESULT_ANALYSIS),
        _ => None,
    }
}

// --------------------------------------------------------------- Mode config
//
// The mode tables and `get_mode_config` helper are read by the test suite to
// pin the Python `MODES` parity, but the agent loop in `agent.rs` doesn't
// gate tool calls on `allowed_actions` yet — Python parity gap. Gated to
// `cfg(test)` so the dead-code lint stays quiet; un-gate the moment the
// agent enforces per-mode tool restrictions.

/// Per-mode policy: which actions the LLM may call, default iteration cap.
/// Mirrors Python `MODES` in `prompts.py`.
#[cfg(test)]
#[derive(Debug, Clone)]
pub struct ModeConfig {
    pub name: &'static str,
    pub allowed_actions: &'static [&'static str],
    pub max_iterations: u32,
}

#[cfg(test)]
const ALLOWED_ATTACK: &[&str] = &[
    "task",
    "workflow",
    "shell",
    "query",
    "follow_up",
    "add_finding",
    "stop",
];
#[cfg(test)]
const ALLOWED_CHAT: &[&str] = &["query", "follow_up", "add_finding", "shell", "stop"];
#[cfg(test)]
const ALLOWED_EXPLOIT: &[&str] = &["task", "workflow", "shell", "add_finding", "stop"];

#[cfg(test)]
pub fn get_mode_config(mode: &str) -> ModeConfig {
    match normalize_mode(mode) {
        "attack" => ModeConfig {
            name: "attack",
            allowed_actions: ALLOWED_ATTACK,
            max_iterations: 5,
        },
        "exploit" => ModeConfig {
            name: "exploit",
            allowed_actions: ALLOWED_EXPLOIT,
            max_iterations: 5,
        },
        _ => ModeConfig {
            name: "chat",
            allowed_actions: ALLOWED_CHAT,
            max_iterations: 5,
        },
    }
}

/// Normalize a mode string. Empty/unknown → "chat" (Python default fallback,
/// changed from previous Rust behaviour which defaulted to "attack" but
/// Python's `get_system_prompt` falls back to chat too — match Python).
pub fn normalize_mode(raw: &str) -> &'static str {
    match raw.trim().to_lowercase().as_str() {
        "attack" | "pentest" => "attack",
        "exploit" => "exploit",
        _ => "chat",
    }
}

// --------------------------------------------------------------- Composition

/// Optional library-reference renderers. Wired by the caller (the `ai/mod.rs`
/// `run()` builds them from the live registries before calling
/// `get_system_prompt`). When `None`, the corresponding section is left out.
#[derive(Debug, Clone, Default)]
pub struct LibraryReference {
    pub meta_options: String,
    pub tasks: String,
    pub workflows: String,
    pub profiles: String,
    pub wordlists: String,
    pub output_types: String,
    /// Comma-separated list of `_type` discriminators (Python parity). Surfaced
    /// in the `<query_types>` block; readers compose it into the prompt where
    /// queryable types matter. Unused by the chat/attack/exploit modes today.
    #[allow(dead_code)]
    pub query_types: String,
}

impl LibraryReference {
    /// Compose into the `<tasks>...</tasks>` block Python emits in
    /// `build_library_reference()`. Empty sections are skipped.
    pub fn render(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        parts.push(REFERENCE_FORMAT.into());
        if !self.meta_options.is_empty() {
            parts.push(wrap("meta_options", &self.meta_options));
        }
        if !self.tasks.is_empty() {
            parts.push(wrap("tasks", &self.tasks));
        }
        if !self.workflows.is_empty() {
            parts.push(wrap("workflows", &self.workflows));
        }
        if !self.profiles.is_empty() {
            parts.push(wrap("profiles", &self.profiles));
        }
        if !self.wordlists.is_empty() {
            parts.push(wrap("wordlists", &self.wordlists));
        }
        if !self.output_types.is_empty() {
            parts.push(wrap("output_types", &self.output_types));
        }
        parts.push(format!(
            "<option_formats>\n{OPTION_FORMATS}\n</option_formats>"
        ));
        parts.join("\n\n")
    }
}

fn wrap(tag: &str, body: &str) -> String {
    format!("<{tag}>\n{body}\n</{tag}>")
}

const REFERENCE_FORMAT: &str = "Format: name|description|[tags]|options|meta:shared_options
- Options: name(type) where type is str, int, float, flag, list, dict, or Choice([...])
- Meta options are shared across tools and defined in <meta_options>. Each task/workflow lists which ones it supports.
- Profiles can be applied to any task/workflow via opts: {\"profiles\": [\"profile_name\"]}";

const OPTION_FORMATS: &str =
    "header|key1:value1;;key2:value2|Multiple headers separated by ;;
cookie|name1=val1;name2=val2|Standard cookie format
proxy|http://host:port|HTTP/SOCKS proxy URL
wordlist|name_or_path|Use predefined name or file path
ports|1-1000,8080,8443|Comma-separated ports or ranges";

/// Render the system prompt for `mode` with `vars` substituted into `$name` /
/// `${name}` placeholders and `${include}` resolved against bundled constraint
/// files. `library` is rendered into `${library_reference}` when the mode
/// asks for it (attack + exploit). Mirrors Python `get_system_prompt`.
pub fn get_system_prompt(
    mode: &str,
    workspace_path: &str,
    library: Option<&LibraryReference>,
) -> String {
    let mode = normalize_mode(mode);
    let template = match mode {
        "attack" => MODE_ATTACK,
        "exploit" => MODE_EXPLOIT,
        _ => MODE_CHAT,
    };

    // First pass: resolve `${include}` tokens that match a bundled constraint.
    // Unmatched tokens are left intact for the variable substitution pass.
    let after_includes = resolve_includes(template);

    // Variable substitution.
    let mut vars: HashMap<&str, String> = HashMap::new();
    let ws = if workspace_path.is_empty() {
        "<workspace>".to_string()
    } else {
        workspace_path.to_string()
    };
    vars.insert("workspace_path", ws);
    if let Some(lib) = library {
        vars.insert("library_reference", lib.render());
    }
    // Chat mode references `${output_types_reference}` directly without the
    // full library wrap (Python parity).
    if let Some(lib) = library {
        if !lib.output_types.is_empty() {
            vars.insert("output_types_reference", lib.output_types.clone());
        }
    }
    safe_substitute(&after_includes, &vars)
}

/// Resolve every `${name}` whose `name` matches a bundled constraint file.
fn resolve_includes(template: &str) -> String {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}").unwrap());
    let mut out = String::with_capacity(template.len());
    let mut last = 0;
    for caps in re.captures_iter(template) {
        let m = caps.get(0).unwrap();
        let name = caps.get(1).unwrap().as_str();
        out.push_str(&template[last..m.start()]);
        if let Some(body) = constraint_body(name) {
            out.push_str(body.trim_end());
        } else {
            // Leave the `${name}` alone — it's a variable placeholder.
            out.push_str(m.as_str());
        }
        last = m.end();
    }
    out.push_str(&template[last..]);
    out
}

/// Python `string.Template.safe_substitute`-equivalent: replace `$name` and
/// `${name}` with `vars[name]`, leave unmatched names intact.
fn safe_substitute(text: &str, vars: &HashMap<&str, String>) -> String {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        // Matches `$$` (escape), `${name}`, or `$name`.
        Regex::new(r"\$\$|\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)").unwrap()
    });
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for caps in re.captures_iter(text) {
        let m = caps.get(0).unwrap();
        out.push_str(&text[last..m.start()]);
        if m.as_str() == "$$" {
            out.push('$');
        } else {
            let name = caps
                .get(1)
                .or_else(|| caps.get(2))
                .map(|x| x.as_str())
                .unwrap_or("");
            if let Some(val) = vars.get(name) {
                out.push_str(val);
            } else {
                out.push_str(m.as_str());
            }
        }
        last = m.end();
    }
    out.push_str(&text[last..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_mode_canonicalizes_known_values() {
        assert_eq!(normalize_mode("attack"), "attack");
        assert_eq!(normalize_mode("ATTACK"), "attack");
        assert_eq!(normalize_mode("pentest"), "attack");
        assert_eq!(normalize_mode("exploit"), "exploit");
        assert_eq!(normalize_mode("chat"), "chat");
        assert_eq!(normalize_mode("nonsense"), "chat");
        assert_eq!(normalize_mode(""), "chat");
    }

    #[test]
    fn mode_config_carries_python_allowed_actions() {
        let a = get_mode_config("attack");
        assert!(a.allowed_actions.contains(&"task"));
        assert!(a.allowed_actions.contains(&"workflow"));
        assert!(a.allowed_actions.contains(&"follow_up"));
        let c = get_mode_config("chat");
        assert!(!c.allowed_actions.contains(&"task"));
        assert!(!c.allowed_actions.contains(&"workflow"));
        assert!(c.allowed_actions.contains(&"query"));
        let e = get_mode_config("exploit");
        assert!(e.allowed_actions.contains(&"task"));
        assert!(!e.allowed_actions.contains(&"follow_up"));
    }

    #[test]
    fn resolve_includes_inlines_known_constraints() {
        let out = resolve_includes("before ${common} after");
        assert!(!out.contains("${common}"));
        assert!(out.contains("before"));
        assert!(out.contains("after"));
        // common.txt content has some actual text — pick a stable token.
        // Without knowing the exact content, just assert the include expanded.
        assert!(out.len() > "before  after".len());
    }

    #[test]
    fn resolve_includes_leaves_unknown_alone() {
        let out = resolve_includes("hello ${unknown_token} world");
        assert!(out.contains("${unknown_token}"));
    }

    #[test]
    fn safe_substitute_replaces_known_and_keeps_unknown() {
        let mut vars = HashMap::new();
        vars.insert("name", "Alice".to_string());
        let out = safe_substitute("Hello $name and $other and ${name}!", &vars);
        assert_eq!(out, "Hello Alice and $other and Alice!");
    }

    #[test]
    fn safe_substitute_handles_dollar_escape() {
        let vars = HashMap::new();
        assert_eq!(safe_substitute("price: $$10", &vars), "price: $10");
    }

    #[test]
    fn attack_prompt_renders_with_library_and_workspace() {
        let lib = LibraryReference {
            tasks: "nmap|Port scan|[port]|ports(str)|meta:threads".into(),
            workflows: "host_recon|Recon|[]|".into(),
            profiles: "aggressive|Loud and fast".into(),
            wordlists: "common\n\nUse remote URLs too.".into(),
            output_types: "vulnerability|name(str),severity(str)".into(),
            ..LibraryReference::default()
        };
        let p = get_system_prompt("attack", "/tmp/reports", Some(&lib));
        assert!(p.contains("/tmp/reports"));
        assert!(p.contains("<tasks>"));
        assert!(p.contains("nmap"));
        assert!(p.contains("<workflows>"));
        assert!(p.contains("host_recon"));
        assert!(p.contains("aggressive"));
    }

    #[test]
    fn chat_prompt_uses_output_types_reference() {
        let lib = LibraryReference {
            output_types: "url|url(str)".into(),
            ..LibraryReference::default()
        };
        let p = get_system_prompt("chat", "/tmp", Some(&lib));
        // Chat templates reference output_types but NOT the full library wrap
        // — we accept either by checking the inner content made it through.
        assert!(p.contains("url"));
    }

    #[test]
    fn unknown_mode_falls_back_to_chat() {
        let p1 = get_system_prompt("hacking-time", "/tmp", None);
        let p2 = get_system_prompt("chat", "/tmp", None);
        assert_eq!(p1, p2);
    }

    #[test]
    fn render_skips_empty_sections() {
        let mut lib = LibraryReference::default();
        lib.tasks = "x".into();
        // No workflows/profiles → those tags don't appear.
        let r = lib.render();
        assert!(r.contains("<tasks>"));
        assert!(!r.contains("<workflows>"));
        assert!(!r.contains("<profiles>"));
        assert!(r.contains("<option_formats>"));
    }
}
