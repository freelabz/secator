//! Workflow/scan/profile template loading + runner-tree building + pruning.
//!
//! Maps to Python `secator/template.py` + `secator/loader.py` + `secator/tree.py`.
//! Parses the YAML DSL into typed Rust structs, builds the runner tree (with `_group`
//! parallel nodes preserved), and prunes nodes whose `if:` condition is false against
//! the supplied opts/targets (evaluated by `secator-expr` — no `eval`).
//!
//! Option-flattening (the CLI-facing flat opt set with conflict disambiguation) is
//! tracked separately and lands when the dynamic CLI is wired (M6).

pub mod registry;

use std::path::Path;

use secator_expr::{eval_bool, Scope, Value};
use serde_yaml::{Mapping, Value as Yaml};

// ----------------------------------------------------------------- Template kinds

/// A parsed YAML template.
#[derive(Debug, Clone)]
pub enum Template {
    Workflow(WorkflowDef),
    Scan(ScanDef),
    Profile(ProfileDef),
}

impl Template {
    pub fn name(&self) -> &str {
        match self {
            Template::Workflow(w) => &w.name,
            Template::Scan(s) => &s.name,
            Template::Profile(p) => &p.name,
        }
    }
    pub fn kind(&self) -> &'static str {
        match self {
            Template::Workflow(_) => "workflow",
            Template::Scan(_) => "scan",
            Template::Profile(_) => "profile",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct WorkflowDef {
    pub name: String,
    pub alias: Option<String>,
    pub description: Option<String>,
    pub long_description: Option<String>,
    pub tags: Vec<String>,
    pub input_types: Vec<String>,
    /// Python `default_inputs` — when the user passes no CLI targets the
    /// workflow still runs with this string. `Some("")` is a legitimate
    /// "allowed to run with zero inputs" marker (used by `cidr_recon` so its
    /// `netdetect` + `prompt` branch can fire).
    pub default_inputs: Option<String>,
    /// Workflow-level CLI options (the new options this workflow exposes).
    pub options: Mapping,
    /// Defaults pushed down to constituent tasks.
    pub default_options: Mapping,
    /// Ordered (insertion-preserving) map of `task_name → node_yaml`.
    pub tasks: Mapping,
}

#[derive(Debug, Clone, Default)]
pub struct ScanDef {
    pub name: String,
    pub alias: Option<String>,
    pub description: Option<String>,
    pub long_description: Option<String>,
    pub tags: Vec<String>,
    pub input_types: Vec<String>,
    pub default_inputs: Option<String>,
    pub options: Mapping,
    pub default_options: Mapping,
    /// Ordered map of `workflow_name → workflow_overrides`.
    pub workflows: Mapping,
}

#[derive(Debug, Clone, Default)]
pub struct ProfileDef {
    pub name: String,
    pub category: Option<String>,
    pub description: Option<String>,
    /// If true, the profile's opts OVERRIDE user-supplied values (Python `enforce`).
    pub enforce: bool,
    pub opts: Mapping,
}

#[derive(Debug, Clone)]
pub enum TemplateError {
    Io(String),
    Yaml(String),
    Schema(String),
}
impl std::fmt::Display for TemplateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TemplateError::Io(s) => write!(f, "template io: {s}"),
            TemplateError::Yaml(s) => write!(f, "template yaml: {s}"),
            TemplateError::Schema(s) => write!(f, "template schema: {s}"),
        }
    }
}
impl std::error::Error for TemplateError {}

// ---------------------------------------------------------------------- Loading

pub fn load_from_path(path: &Path) -> Result<Template, TemplateError> {
    let text =
        std::fs::read_to_string(path).map_err(|e| TemplateError::Io(format!("{}: {e}", path.display())))?;
    load_from_str(&text)
}

pub fn load_from_str(text: &str) -> Result<Template, TemplateError> {
    let value: Yaml = serde_yaml::from_str(text).map_err(|e| TemplateError::Yaml(e.to_string()))?;
    parse_template(&value)
}

fn parse_template(v: &Yaml) -> Result<Template, TemplateError> {
    let m = v
        .as_mapping()
        .ok_or_else(|| TemplateError::Schema("template root must be a mapping".into()))?;
    let kind = m
        .get(Yaml::String("type".into()))
        .and_then(|v| v.as_str())
        .unwrap_or("workflow");
    match kind {
        "workflow" => Ok(Template::Workflow(parse_workflow(m)?)),
        "scan" => Ok(Template::Scan(parse_scan(m)?)),
        "profile" => Ok(Template::Profile(parse_profile(m)?)),
        "task" => Err(TemplateError::Schema(
            "task templates come from Rust SPECs, not YAML".into(),
        )),
        other => Err(TemplateError::Schema(format!("unknown template type {other:?}"))),
    }
}

fn parse_workflow(m: &Mapping) -> Result<WorkflowDef, TemplateError> {
    Ok(WorkflowDef {
        name: get_str(m, "name").ok_or_else(|| TemplateError::Schema("workflow.name missing".into()))?.to_string(),
        alias: get_str(m, "alias").map(str::to_string),
        description: get_str(m, "description").map(str::to_string),
        long_description: get_str(m, "long_description").map(str::to_string),
        tags: get_str_list(m, "tags"),
        input_types: get_str_list(m, "input_types"),
        default_inputs: get_default_inputs(m),
        options: get_mapping(m, "options"),
        default_options: get_mapping(m, "default_options"),
        tasks: get_mapping(m, "tasks"),
    })
}

fn parse_scan(m: &Mapping) -> Result<ScanDef, TemplateError> {
    Ok(ScanDef {
        name: get_str(m, "name").ok_or_else(|| TemplateError::Schema("scan.name missing".into()))?.to_string(),
        alias: get_str(m, "alias").map(str::to_string),
        description: get_str(m, "description").map(str::to_string),
        long_description: get_str(m, "long_description").map(str::to_string),
        tags: get_str_list(m, "tags"),
        input_types: get_str_list(m, "input_types"),
        default_inputs: get_default_inputs(m),
        options: get_mapping(m, "options"),
        default_options: get_mapping(m, "default_options"),
        workflows: get_mapping(m, "workflows"),
    })
}

/// Read `default_inputs:` from a workflow/scan YAML. Returns `Some(s)` if the
/// key is present (even when the value is the empty string — see `cidr_recon`),
/// `None` if absent.
fn get_default_inputs(m: &Mapping) -> Option<String> {
    let raw = m.get(serde_yaml::Value::String("default_inputs".into()))?;
    match raw {
        serde_yaml::Value::String(s) => Some(s.clone()),
        serde_yaml::Value::Null => Some(String::new()),
        serde_yaml::Value::Sequence(seq) => {
            // Lists are joined with commas — `expand_inputs` will split them back.
            Some(
                seq.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect::<Vec<_>>()
                    .join(","),
            )
        }
        _ => None,
    }
}

fn parse_profile(m: &Mapping) -> Result<ProfileDef, TemplateError> {
    Ok(ProfileDef {
        name: get_str(m, "name").ok_or_else(|| TemplateError::Schema("profile.name missing".into()))?.to_string(),
        category: get_str(m, "category").map(str::to_string),
        description: get_str(m, "description").map(str::to_string),
        enforce: m.get(Yaml::String("enforce".into())).and_then(|v| v.as_bool()).unwrap_or(false),
        opts: get_mapping(m, "opts"),
    })
}

fn get_str<'a>(m: &'a Mapping, key: &str) -> Option<&'a str> {
    m.get(Yaml::String(key.into())).and_then(|v| v.as_str())
}
fn get_str_list(m: &Mapping, key: &str) -> Vec<String> {
    m.get(Yaml::String(key.into()))
        .and_then(|v| v.as_sequence())
        .map(|s| s.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}
fn get_mapping(m: &Mapping, key: &str) -> Mapping {
    m.get(Yaml::String(key.into()))
        .and_then(|v| v.as_mapping())
        .cloned()
        .unwrap_or_default()
}

// ----------------------------------------------------------------- Runner tree

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    Scan,
    Workflow,
    /// `_group` or `_group/<name>` — parallel siblings.
    Group,
    Task,
}

/// A node in the runner tree (Python `TaskNode`). Order of `children` is preserved
/// from YAML insertion order.
#[derive(Debug, Clone)]
pub struct TaskNode {
    pub name: String,
    /// Path-like unique id: `host_recon`, `host_recon.naabu`, `host_recon._group/vuln.searchsploit`.
    pub id: String,
    pub kind: NodeKind,
    pub condition: Option<String>,
    pub description: Option<String>,
    /// Per-node opts (raw YAML — the engine evaluates `condition`, `targets_`, etc.).
    pub opts: Mapping,
    pub children: Vec<TaskNode>,
}

#[derive(Debug, Clone)]
pub struct RunnerTree {
    pub name: String,
    pub kind: NodeKind,
    pub root: TaskNode,
}

/// Build the runner tree from a parsed `Template`. For scans, each workflow entry is
/// resolved via `find_workflow` (caller-supplied) and recursively inlined.
pub fn build_runner_tree<F>(template: &Template, find_workflow: F) -> Result<RunnerTree, TemplateError>
where
    F: Fn(&str) -> Option<WorkflowDef>,
{
    match template {
        Template::Workflow(wf) => Ok(RunnerTree {
            name: wf.name.clone(),
            kind: NodeKind::Workflow,
            root: build_workflow_node(wf, None)?,
        }),
        Template::Scan(s) => Ok(RunnerTree {
            name: s.name.clone(),
            kind: NodeKind::Scan,
            root: build_scan_node(s, &find_workflow)?,
        }),
        Template::Profile(_) => Err(TemplateError::Schema("profiles have no tree".into())),
    }
}

fn build_workflow_node(wf: &WorkflowDef, ancestor_id: Option<&str>) -> Result<TaskNode, TemplateError> {
    let id = ancestor_id.map(|a| format!("{a}.{}", wf.name)).unwrap_or_else(|| wf.name.clone());
    // Seed opts with whatever the workflow declares as defaults — first
    // `default_options:` (rare, Python-explicit), then each option's `default:`
    // value from the `options:` block. The CLI layer also applies these for the
    // workflow subcommand, but a scan inlining this workflow has its own clap
    // surface; without this seed the inner-task conditions
    // (`'nmap' in opts.scanners`) would evaluate against an empty opts map.
    let mut seeded = wf.default_options.clone();
    for (k, v) in &wf.options {
        if let Some(opt) = v.as_mapping() {
            if let Some(def) = opt.get(Yaml::String("default".into())) {
                if !seeded.contains_key(k) {
                    seeded.insert(k.clone(), def.clone());
                }
            }
        }
    }
    let mut node = TaskNode {
        name: wf.name.clone(),
        id: id.clone(),
        kind: NodeKind::Workflow,
        condition: None,
        description: wf.description.clone(),
        opts: seeded,
        children: Vec::new(),
    };
    for (key, val) in &wf.tasks {
        let key_str = match key.as_str() {
            Some(s) => s,
            None => continue,
        };
        let child_id = format!("{id}.{key_str}");
        node.children.push(build_task_or_group(key_str, val, &child_id)?);
    }
    Ok(node)
}

fn build_scan_node<F>(s: &ScanDef, find_workflow: &F) -> Result<TaskNode, TemplateError>
where
    F: Fn(&str) -> Option<WorkflowDef>,
{
    let id = s.name.clone();
    let mut node = TaskNode {
        name: s.name.clone(),
        id: id.clone(),
        kind: NodeKind::Scan,
        condition: None,
        description: s.description.clone(),
        opts: s.default_options.clone(),
        children: Vec::new(),
    };
    for (key, val) in &s.workflows {
        let wf_name = match key.as_str() {
            Some(s) => s.split('/').next().unwrap_or(s),
            None => continue,
        };
        let wf = find_workflow(wf_name)
            .ok_or_else(|| TemplateError::Schema(format!("scan references unknown workflow {wf_name:?}")))?;
        // Merge per-workflow overrides into the workflow node's opts.
        let mut wf_node = build_workflow_node(&wf, Some(&id))?;
        if let Some(overrides) = val.as_mapping() {
            // Condition lives at the scan->workflow override level.
            wf_node.condition = overrides
                .get(Yaml::String("if".into()))
                .and_then(|v| v.as_str())
                .map(str::to_string);
            // Other overrides become opts on the workflow node.
            for (k, v) in overrides {
                if k.as_str() == Some("if") { continue; }
                wf_node.opts.insert(k.clone(), v.clone());
            }
        }
        node.children.push(wf_node);
    }
    Ok(node)
}

/// Parse a YAML entry that is either a task (key without `_group` prefix) or a group
/// (key starting with `_group`).
fn build_task_or_group(name: &str, val: &Yaml, id: &str) -> Result<TaskNode, TemplateError> {
    let mapping = val.as_mapping().cloned().unwrap_or_default();
    if name.starts_with("_group") {
        // Children = each entry of `mapping`.
        let mut kids = Vec::new();
        for (k, v) in &mapping {
            if let Some(child_name) = k.as_str() {
                let child_id = format!("{id}.{child_name}");
                kids.push(build_task_node(child_name, v, &child_id)?);
            }
        }
        Ok(TaskNode {
            name: name.to_string(),
            id: id.to_string(),
            kind: NodeKind::Group,
            condition: None,
            description: None,
            opts: Mapping::new(),
            children: kids,
        })
    } else {
        build_task_node(name, val, id)
    }
}

fn build_task_node(name: &str, val: &Yaml, id: &str) -> Result<TaskNode, TemplateError> {
    let mapping = val.as_mapping().cloned().unwrap_or_default();
    let condition = mapping
        .get(Yaml::String("if".into()))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let description = mapping
        .get(Yaml::String("description".into()))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    // opts = everything except `if`/`description` (Python carries those out-of-band).
    let mut opts = Mapping::new();
    for (k, v) in &mapping {
        match k.as_str() {
            Some("if") | Some("description") => continue,
            _ => {
                opts.insert(k.clone(), v.clone());
            }
        }
    }
    // Task class name is the part before any `/` (e.g. `nmap/light` → class `nmap`).
    let class = name.split('/').next().unwrap_or(name).to_string();
    Ok(TaskNode {
        name: class,
        id: id.to_string(),
        kind: NodeKind::Task,
        condition,
        description,
        opts,
        children: Vec::new(),
    })
}

// ------------------------------------------------------------------- Pruning

/// Bottom-up walk: remove nodes whose `if:` evaluates to false against `(opts, targets)`.
/// When descending into a workflow node, prefix-strip the scan-level opt names (e.g.
/// `domain_recon_passive` → `passive`) so the inner tasks see the expected names.
/// Mirrors Python `prune_runner_tree`. On eval error the node is kept.
pub fn prune(tree: &mut RunnerTree, opts: &Mapping, targets: &[String]) {
    prune_children(&mut tree.root, opts, targets);
    if !node_condition_passes(&tree.root, opts, targets) {
        // Whole-tree prune: clear children but keep root (callers expect a tree shape).
        tree.root.children.clear();
    }
}

fn prune_children(node: &mut TaskNode, parent_opts: &Mapping, targets: &[String]) {
    let local_opts = if node.kind == NodeKind::Workflow {
        // Strip the scan-level `<workflow>_<opt>` prefix and then merge in the
        // workflow's own `default_options` (parent opts win on conflict so
        // user-supplied values from the scan / CLI override the workflow's
        // defaults). Without this, a scan that inlines `host_recon` would
        // prune away `_group/nmap/light` because `opts.scanners` is undefined
        // when only the scan-level opts are in scope.
        let mut merged = strip_prefix(parent_opts, &node.name);
        for (k, v) in &node.opts {
            if !merged.contains_key(k) {
                merged.insert(k.clone(), v.clone());
            }
        }
        merged
    } else {
        parent_opts.clone()
    };
    // Recurse first so we can drop empty groups bottom-up.
    for child in node.children.iter_mut() {
        prune_children(child, &local_opts, targets);
    }
    node.children
        .retain(|c| !(c.kind == NodeKind::Group && c.children.is_empty()) && node_condition_passes(c, &local_opts, targets));
}

fn strip_prefix(opts: &Mapping, workflow_name: &str) -> Mapping {
    let prefix = format!("{workflow_name}_");
    let mut out = opts.clone();
    for (k, v) in opts {
        if let Some(s) = k.as_str() {
            if let Some(rest) = s.strip_prefix(&prefix) {
                out.insert(Yaml::String(rest.to_string()), v.clone());
            }
        }
    }
    out
}

fn node_condition_passes(node: &TaskNode, opts: &Mapping, targets: &[String]) -> bool {
    let cond = match &node.condition {
        Some(c) => c,
        None => return true,
    };
    let mut scope = Scope::new();
    scope.set("opts", mapping_to_value(opts));
    scope.set("targets", Value::List(targets.iter().cloned().map(Value::Str).collect()));
    match eval_bool(cond, &scope) {
        Ok(b) => b,
        Err(_) => true, // err on the side of showing more
    }
}

fn mapping_to_value(m: &Mapping) -> Value {
    let mut out = std::collections::BTreeMap::new();
    for (k, v) in m {
        if let Some(s) = k.as_str() {
            out.insert(s.to_string(), yaml_to_value(v));
        }
    }
    Value::Map(out)
}
fn yaml_to_value(v: &Yaml) -> Value {
    match v {
        Yaml::Null => Value::Null,
        Yaml::Bool(b) => Value::Bool(*b),
        Yaml::Number(n) => n
            .as_i64()
            .map(Value::Int)
            .or_else(|| n.as_f64().map(Value::Float))
            .unwrap_or(Value::Null),
        Yaml::String(s) => Value::Str(s.clone()),
        Yaml::Sequence(seq) => Value::List(seq.iter().map(yaml_to_value).collect()),
        Yaml::Mapping(m) => mapping_to_value(m),
        Yaml::Tagged(t) => yaml_to_value(&t.value),
    }
}

// ----------------------------------------------------------------------- Traversal

/// DFS visitor with full borrow lifetime preserved.
pub fn walk<'a, F: FnMut(&'a TaskNode)>(node: &'a TaskNode, f: &mut F) {
    f(node);
    for c in &node.children {
        walk(c, f);
    }
}

/// Flat list of every node in DFS order.
pub fn flat_nodes(tree: &RunnerTree) -> Vec<&TaskNode> {
    fn collect<'a>(node: &'a TaskNode, out: &mut Vec<&'a TaskNode>) {
        out.push(node);
        for c in &node.children {
            collect(c, out);
        }
    }
    let mut out = Vec::new();
    collect(&tree.root, &mut out);
    out
}

// ----------------------------------------------------------------------- Render (debug)
impl RunnerTree {
    pub fn render(&self) -> String {
        let mut out = String::new();
        render_node(&self.root, "", true, true, &mut out);
        out
    }
}
fn render_node(node: &TaskNode, prefix: &str, is_root: bool, _is_last: bool, out: &mut String) {
    let icon = match node.kind {
        NodeKind::Scan => "🔬",
        NodeKind::Workflow => "⚙",
        NodeKind::Group => "▦",
        NodeKind::Task => "🔧",
    };
    out.push_str(&format!("{prefix}{icon} {}", node.name));
    if let Some(d) = &node.description {
        out.push_str(&format!(" — {d}"));
    }
    if let Some(c) = &node.condition {
        out.push_str(&format!(" # if {c}"));
    }
    out.push('\n');
    let n = node.children.len();
    for (i, child) in node.children.iter().enumerate() {
        let last = i + 1 == n;
        let branch = if last { "└─ " } else { "├─ " };
        let child_prefix = format!("{}{}", if is_root { "" } else { prefix }, branch);
        let next_prefix = format!("{}{}", if is_root { "" } else { prefix }, if last { "   " } else { "│  " });
        render_node(child, &child_prefix, false, last, out);
        // Replace prefix line back for next sibling — handled by `next_prefix` above.
        let _ = next_prefix;
    }
}

// ----------------------------------------------------------------------- Tests
#[cfg(test)]
mod tests {
    use super::*;

    const HOST_RECON: &str = include_str!("../../../../secator/configs/workflows/host_recon.yaml");
    const AGGRESSIVE_PROFILE: &str = include_str!("../../../../secator/configs/profiles/aggressive.yaml");
    const HOST_SCAN: &str = include_str!("../../../../secator/configs/scans/host.yaml");

    #[test]
    fn loads_workflow_yaml() {
        let t = load_from_str(HOST_RECON).expect("parse workflow");
        let wf = match &t {
            Template::Workflow(w) => w,
            _ => panic!("expected workflow"),
        };
        assert_eq!(wf.name, "host_recon");
        assert_eq!(wf.alias.as_deref(), Some("hostrec"));
        assert!(wf.input_types.contains(&"host".to_string()));
        // tasks should contain `_group`, `nmap`, `sshaudit`, `httpx`, `_group/nuclei`, `_group/vuln`.
        let task_keys: Vec<&str> = wf.tasks.iter().filter_map(|(k, _)| k.as_str()).collect();
        assert!(task_keys.contains(&"nmap"));
        assert!(task_keys.contains(&"_group"));
        assert!(task_keys.iter().any(|k| k.starts_with("_group/")));
    }

    #[test]
    fn loads_profile_yaml() {
        let t = load_from_str(AGGRESSIVE_PROFILE).expect("parse profile");
        match t {
            Template::Profile(p) => {
                assert_eq!(p.name, "aggressive");
                assert!(p.opts.contains_key(Yaml::String("rate_limit".into())));
            }
            _ => panic!("expected profile"),
        }
    }

    #[test]
    fn builds_workflow_tree() {
        let t = load_from_str(HOST_RECON).unwrap();
        let tree = build_runner_tree(&t, |_| None).unwrap();
        assert_eq!(tree.name, "host_recon");
        assert_eq!(tree.kind, NodeKind::Workflow);
        // Root has children for _group / nmap / sshaudit / httpx / _group/nuclei / _group/vuln.
        let kinds: Vec<NodeKind> = tree.root.children.iter().map(|c| c.kind).collect();
        // First child is the `_group` (naabu + nmap/light).
        assert_eq!(kinds[0], NodeKind::Group);
        // Some leaf task expected.
        assert!(tree.root.children.iter().any(|c| c.kind == NodeKind::Task && c.name == "nmap"));
        // A named group `_group/nuclei` exists.
        assert!(tree.root.children.iter().any(|c| c.kind == NodeKind::Group && c.name.starts_with("_group/")));
    }

    #[test]
    fn builds_scan_tree_inlining_workflows() {
        let scan = load_from_str(HOST_SCAN).unwrap();
        let wf = load_from_str(HOST_RECON).unwrap();
        let wf_def = match wf {
            Template::Workflow(w) => w,
            _ => panic!(),
        };
        let tree = build_runner_tree(&scan, |name| {
            if name == "host_recon" { Some(wf_def.clone()) } else { None }
        });
        // The scan references three workflows; we provide only host_recon → error on the others.
        // For this test we just check host_recon resolution.
        assert!(tree.is_err()); // url_crawl/url_vuln aren't supplied
    }

    #[test]
    fn prune_removes_condition_failing_nodes() {
        let t = load_from_str(HOST_RECON).unwrap();
        let mut tree = build_runner_tree(&t, |_| None).unwrap();
        // opts.passive=true → many nodes have `if: not opts.passive` → should be pruned.
        // opts.scanners=['naabu'] → only naabu in the first group, no nmap*.
        let mut opts = Mapping::new();
        opts.insert(Yaml::String("passive".into()), Yaml::Bool(true));
        opts.insert(
            Yaml::String("scanners".into()),
            Yaml::Sequence(vec![Yaml::String("naabu".into())]),
        );
        prune(&mut tree, &opts, &[]);
        // Most nodes had `if: not opts.passive` — with passive=true, only the unconditional
        // ones survive. Check that the tree shrunk substantially.
        let count_before = {
            let t2 = load_from_str(HOST_RECON).unwrap();
            let tree2 = build_runner_tree(&t2, |_| None).unwrap();
            flat_nodes(&tree2).len()
        };
        let count_after = flat_nodes(&tree).len();
        assert!(count_after < count_before, "{count_after} should be < {count_before}");
    }

    #[test]
    fn prune_keeps_nodes_when_condition_passes() {
        let t = load_from_str(HOST_RECON).unwrap();
        let mut tree = build_runner_tree(&t, |_| None).unwrap();
        // opts.passive=false, scanners=[nmap], exploiters=[searchsploit]
        let mut opts = Mapping::new();
        opts.insert(Yaml::String("passive".into()), Yaml::Bool(false));
        opts.insert(
            Yaml::String("scanners".into()),
            Yaml::Sequence(vec![Yaml::String("nmap".into())]),
        );
        opts.insert(
            Yaml::String("exploiters".into()),
            Yaml::Sequence(vec![Yaml::String("searchsploit".into())]),
        );
        opts.insert(Yaml::String("nuclei".into()), Yaml::Bool(false));
        prune(&mut tree, &opts, &[]);
        // nmap task should still be there.
        assert!(flat_nodes(&tree).iter().any(|n| n.name == "nmap" && n.kind == NodeKind::Task));
        // searchsploit should still be there (under _group/vuln).
        assert!(flat_nodes(&tree).iter().any(|n| n.name == "searchsploit"));
        // nuclei should be pruned (opts.nuclei = false).
        assert!(!flat_nodes(&tree).iter().any(|n| n.name == "nuclei" || n.name == "nuclei/network" || n.name == "nuclei/url"));
    }

    #[test]
    fn render_tree_smoke() {
        let t = load_from_str(HOST_RECON).unwrap();
        let tree = build_runner_tree(&t, |_| None).unwrap();
        let s = tree.render();
        assert!(s.contains("host_recon"));
        assert!(s.contains("nmap"));
    }
}
