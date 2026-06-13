//! DAG: compile a pruned runner tree to a `Plan` (chain/group/chord) and evaluate
//! extractors (`targets_` / `<opt>_`) against accumulated results.
//!
//! Maps to Python `build_celery_workflow` + `runners/_helpers.py::run_extractors`. See
//! `../docs/rewrite/02-architecture.md` §6 and §8.
//!
//! M4b scope: in-process composition + extractor evaluation. Chord (parallel-then-join)
//! is collapsed to Group + a follow-on join inside `secator-exec`. Scope/ancestry
//! filtering is implemented at evaluator level so extractors only consume their own
//! subtree's results.

use std::collections::BTreeMap;

use secator_expr::{eval_bool, Scope, Value as ExprValue};
use secator_model::OutputItem;
use secator_templates::{NodeKind, RunnerTree, TaskNode};
use serde_yaml::{Mapping, Value as Yaml};

// ----------------------------------------------------------------------- Plan

/// The composition graph the executor walks.
#[derive(Debug, Clone)]
pub enum Plan {
    /// Run one task (class name) with these inputs/opts. Inputs may be resolved from
    /// extractors at runtime when this `Plan` is executed.
    Task(TaskPlan),
    /// Sequential (chain).
    Chain(Vec<Plan>),
    /// Parallel (group).
    Group(Vec<Plan>),
}

#[derive(Debug, Clone, Default)]
pub struct TaskPlan {
    /// Task class name (e.g. `"nmap"` — the part before `/` in `nmap/light`).
    pub class: String,
    /// Node id, e.g. `host_recon.nmap` or `host_recon._group.nmap/light` — used for
    /// scope/ancestry tagging on results.
    pub id: String,
    /// Defaults inherited from the enclosing workflow / scan / group's
    /// `options:` and `default_options:` blocks. LOWEST priority — runtime
    /// parent opts (CLI flags + profile-applied values) win, and the task's
    /// own [`Self::opts`] win on top of that. Python parity: `--pf passive`
    /// must override a workflow's `options.passive.default = false`.
    pub ancestor_defaults: BTreeMap<String, ExprValue>,
    /// The task's OWN static opts declared on its YAML node (e.g. `gf/xss`'s
    /// `pattern: xss`). HIGHEST priority — wins over both ancestor defaults
    /// and parent runtime opts.
    pub opts: BTreeMap<String, ExprValue>,
    /// Extractors that compute the task's inputs at runtime (Python `targets_`).
    pub target_extractors: Vec<Extractor>,
    /// Extractors that compute a named opt at runtime (Python `<opt>_`).
    pub opt_extractors: BTreeMap<String, Vec<Extractor>>,
    /// `if:` condition; re-checked at exec time against accumulated results.
    pub condition: Option<String>,
    /// `<ancestor>` node id; used by extractors to scope which results to consume.
    pub ancestor_id: Option<String>,
    /// Description shown in lifecycle messages.
    pub description: Option<String>,
}

/// A single extractor entry (Python: `{type, field, condition, group_by}` or shorthand
/// `"type.field"`).
#[derive(Debug, Clone)]
pub struct Extractor {
    pub kind: String,
    pub field: String,
    pub condition: Option<String>,
    pub group_by: Option<String>,
}

// ----------------------------------------------------------------------- Compile

pub fn compile(tree: &RunnerTree) -> Plan {
    compile_node(&tree.root, None, &BTreeMap::new())
}

/// `inherited_opts` accumulates the static opts seen on every ancestor workflow /
/// scan node, so a leaf task inherits its enclosing workflow's defaults at exec
/// time (Python parity: `host_recon`'s `scanners: [nmap]` default has to reach the
/// child `if` checks even when a scan inlines the workflow and the top-level CLI
/// surface doesn't declare `--scanners`).
fn compile_node(
    node: &TaskNode,
    ancestor_id: Option<&str>,
    inherited_opts: &BTreeMap<String, ExprValue>,
) -> Plan {
    let next_ancestor = match node.kind {
        NodeKind::Workflow | NodeKind::Scan => Some(node.id.as_str()),
        _ => ancestor_id,
    };
    // Fold this node's static opts into the inherited map for the children. Task
    // nodes never push: their opts are local to the task itself (handled inside
    // `task_plan`).
    let mut child_inherited = inherited_opts.clone();
    if matches!(node.kind, NodeKind::Workflow | NodeKind::Scan | NodeKind::Group) {
        for (k, v) in &node.opts {
            let key = match k.as_str() { Some(s) => s, None => continue };
            if key.ends_with('_') { continue; } // extractors stay on their own node
            child_inherited.insert(key.to_string(), yaml_to_value(v));
        }
    }
    match node.kind {
        NodeKind::Task => Plan::Task(task_plan(node, next_ancestor, inherited_opts)),
        NodeKind::Group => Plan::Group(
            node.children.iter().map(|c| compile_node(c, next_ancestor, &child_inherited)).collect(),
        ),
        NodeKind::Workflow | NodeKind::Scan => {
            let mut items: Vec<Plan> = node
                .children
                .iter()
                .map(|c| compile_node(c, next_ancestor, &child_inherited))
                .collect();
            // Collapse a 1-child group to its child (Python parity).
            for item in items.iter_mut() {
                if let Plan::Group(g) = item {
                    if g.len() == 1 {
                        *item = g.remove(0);
                    }
                }
            }
            Plan::Chain(items)
        }
    }
}

fn task_plan(
    node: &TaskNode,
    ancestor_id: Option<&str>,
    inherited_opts: &BTreeMap<String, ExprValue>,
) -> TaskPlan {
    // Keep workflow / scan inherited defaults SEPARATE from the task's own
    // declared opts. The execution merge in `secator-exec::execute_task`
    // applies them as: `ancestor_defaults < parent_runtime_opts < own_opts`
    // — Python parity. Mixing them at compile time (which the old code did)
    // caused workflow `options.<name>.default` values to clobber profile /
    // CLI runtime overrides — see B-WF-PASSIVE.
    let ancestor_defaults = inherited_opts.clone();
    let mut own_opts: BTreeMap<String, ExprValue> = BTreeMap::new();
    let mut target_extractors: Vec<Extractor> = Vec::new();
    let mut opt_extractors: BTreeMap<String, Vec<Extractor>> = BTreeMap::new();
    for (k, v) in &node.opts {
        let key = match k.as_str() {
            Some(s) => s,
            None => continue,
        };
        // Trailing underscore = extractor (Python convention).
        if let Some(base) = key.strip_suffix('_') {
            let extractors = parse_extractor_list(v);
            if base == "targets" {
                target_extractors = extractors;
            } else {
                opt_extractors.insert(base.to_string(), extractors);
            }
        } else {
            own_opts.insert(key.to_string(), yaml_to_value(v));
        }
    }
    TaskPlan {
        class: node.name.clone(),
        id: node.id.clone(),
        ancestor_defaults,
        opts: own_opts,
        target_extractors,
        opt_extractors,
        condition: node.condition.clone(),
        ancestor_id: ancestor_id.map(str::to_string),
        description: node.description.clone(),
    }
}

fn parse_extractor_list(v: &Yaml) -> Vec<Extractor> {
    let seq = match v.as_sequence() {
        Some(s) => s,
        None => return Vec::new(),
    };
    seq.iter().filter_map(parse_extractor).collect()
}

fn parse_extractor(v: &Yaml) -> Option<Extractor> {
    // Shorthand string form: `"type.field"`.
    if let Some(s) = v.as_str() {
        let (kind, field) = s.split_once('.')?;
        return Some(Extractor {
            kind: kind.to_string(),
            field: field.to_string(),
            condition: None,
            group_by: None,
        });
    }
    // Dict form.
    let m = v.as_mapping()?;
    let kind = m.get(Yaml::String("type".into())).and_then(|x| x.as_str())?.to_string();
    let field = m.get(Yaml::String("field".into())).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let condition = m.get(Yaml::String("condition".into())).and_then(|x| x.as_str()).map(str::to_string);
    let group_by = m.get(Yaml::String("group_by".into())).and_then(|x| x.as_str()).map(str::to_string);
    Some(Extractor { kind, field, condition, group_by })
}

// --------------------------------------------------------- Extractor runtime

/// Resolve a task's inputs at exec time by running its `target_extractors` against the
/// accumulated `results`, filtered by ancestry/scope. Falls back to `default_inputs` if
/// no extractor matches. Mirrors Python `run_extractors`.
pub fn resolve_inputs(
    plan: &TaskPlan,
    results: &[OutputItem],
    opts: &BTreeMap<String, ExprValue>,
    default_inputs: &[String],
) -> Vec<String> {
    if plan.target_extractors.is_empty() {
        return default_inputs.to_vec();
    }
    let mut out: Vec<String> = Vec::new();
    for ex in &plan.target_extractors {
        // Phase 1: collect items that pass kind / ancestry / condition gates.
        let filtered: Vec<&OutputItem> = results
            .iter()
            .filter(|item| item.type_name() == ex.kind)
            .filter(|item| {
                if let Some(anc) = &plan.ancestor_id {
                    let item_anc = item
                        .meta()
                        .context
                        .get("ancestor_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if !item_anc.is_empty() && item_anc != anc {
                        return false;
                    }
                }
                if let Some(cond) = &ex.condition {
                    let item_value = item_to_value(item);
                    let mut scope = Scope::new();
                    scope.set("item", item_value.clone());
                    scope.set(&ex.kind, item_value);
                    scope.set("opts", opts_to_value(opts));
                    if !eval_bool(cond, &scope).unwrap_or(true) {
                        return false;
                    }
                }
                true
            })
            .collect();

        // Phase 2: with `group_by`, collapse items into one target per group
        // (Python `_run_extractor` group_by branch). Each group joins the unique
        // `prefix`es (left of `~` in the formatted field, or the whole field if
        // no `~`) and re-suffixes with `~<group_key>` when the field had a `~`.
        if let Some(gb_template) = &ex.group_by {
            // Use BTreeMap so the output order is stable (Python uses dict order
            // by first insertion; close enough for tests + observability).
            use std::collections::BTreeMap;
            let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
            let mut group_order: Vec<String> = Vec::new();
            let field_has_tilde = ex.field.contains('~');
            for item in &filtered {
                let item_value = item_to_value(item);
                let group_key = match format_field(gb_template, &item_value) {
                    Some(k) if !k.is_empty() => k,
                    _ => continue,
                };
                let value = match format_field(&ex.field, &item_value) {
                    Some(v) if !v.is_empty() => v,
                    _ => continue,
                };
                let prefix = if field_has_tilde {
                    value.splitn(2, '~').next().unwrap_or("").to_string()
                } else {
                    value
                };
                if prefix.is_empty() {
                    continue;
                }
                let bucket = groups.entry(group_key.clone()).or_insert_with(|| {
                    group_order.push(group_key.clone());
                    Vec::new()
                });
                if !bucket.contains(&prefix) {
                    bucket.push(prefix);
                }
            }
            for key in &group_order {
                let prefixes = &groups[key];
                let joined = prefixes.join(",");
                if field_has_tilde {
                    out.push(format!("{joined}~{key}"));
                } else {
                    out.push(joined);
                }
            }
            continue;
        }

        // No group_by: just format each item's field.
        for item in filtered {
            let item_value = item_to_value(item);
            if let Some(formatted) = format_field(&ex.field, &item_value) {
                if !formatted.is_empty() {
                    out.push(formatted);
                }
            }
        }
    }
    dedupe_preserving_order(out)
}

/// Resolve dynamic opt values (the `<opt>_` keys) at exec time. Returns a new opts map
/// where each dynamic key contributes a comma-joined list of matched values.
pub fn resolve_opts(
    plan: &TaskPlan,
    results: &[OutputItem],
    opts: &BTreeMap<String, ExprValue>,
) -> BTreeMap<String, ExprValue> {
    let mut out = opts.clone();
    for (opt_name, extractors) in &plan.opt_extractors {
        let mut values = Vec::new();
        for ex in extractors {
            for item in results {
                if item.type_name() != ex.kind {
                    continue;
                }
                let item_value = item_to_value(item);
                if let Some(cond) = &ex.condition {
                    let mut scope = Scope::new();
                    scope.set("item", item_value.clone());
                    scope.set(&ex.kind, item_value.clone());
                    scope.set("opts", opts_to_value(opts));
                    if eval_bool(cond, &scope).unwrap_or(true) == false {
                        continue;
                    }
                }
                if let Some(s) = format_field(&ex.field, &item_value) {
                    if !s.is_empty() { values.push(s); }
                }
            }
        }
        let unique = dedupe_preserving_order(values);
        if !unique.is_empty() {
            out.insert(opt_name.clone(), ExprValue::Str(unique.join(",")));
        }
    }
    out
}

/// Format a field template like `{host}:{port}` or `{matched_at}~{id}` by replacing
/// each `{key}` (dotted ok) with the nested value extracted from the item's map.
fn format_field(template: &str, item_value: &ExprValue) -> Option<String> {
    // Bare field name (no braces) → treat as `{field}`.
    let templated = if template.contains('{') && template.contains('}') {
        template.to_string()
    } else {
        format!("{{{template}}}")
    };
    let mut out = String::with_capacity(templated.len());
    let bytes = templated.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c == '{' {
            // find matching '}'
            let end = match templated[i + 1..].find('}') {
                Some(e) => i + 1 + e,
                None => return None,
            };
            let key = &templated[i + 1..end];
            let val = lookup_nested(item_value, key);
            match val {
                Some(s) if !s.is_empty() => out.push_str(&s),
                _ => return None,
            }
            i = end + 1;
        } else {
            out.push(c);
            i += 1;
        }
    }
    Some(out)
}

fn lookup_nested(value: &ExprValue, key: &str) -> Option<String> {
    let mut current = value.clone();
    for part in key.split('.') {
        current = match current {
            ExprValue::Map(m) => m.get(part).cloned()?,
            _ => return None,
        };
    }
    Some(match current {
        ExprValue::Str(s) => s,
        ExprValue::Int(i) => i.to_string(),
        ExprValue::Float(f) => f.to_string(),
        ExprValue::Bool(b) => b.to_string(),
        ExprValue::Null => String::new(),
        ExprValue::List(_) | ExprValue::Map(_) => return None,
    })
}

fn dedupe_preserving_order(values: Vec<String>) -> Vec<String> {
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(values.len());
    for v in values {
        if seen.insert(v.clone()) {
            out.push(v);
        }
    }
    out
}

// ----------------------------------------------------------------------- conv

fn item_to_value(item: &OutputItem) -> ExprValue {
    let map = item.to_map();
    let json: serde_json::Value = serde_json::Value::Object(map);
    ExprValue::from(&json)
}

fn opts_to_value(opts: &BTreeMap<String, ExprValue>) -> ExprValue {
    ExprValue::Map(opts.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
}

fn yaml_to_value(v: &Yaml) -> ExprValue {
    match v {
        Yaml::Null => ExprValue::Null,
        Yaml::Bool(b) => ExprValue::Bool(*b),
        Yaml::Number(n) => n
            .as_i64()
            .map(ExprValue::Int)
            .or_else(|| n.as_f64().map(ExprValue::Float))
            .unwrap_or(ExprValue::Null),
        Yaml::String(s) => ExprValue::Str(s.clone()),
        Yaml::Sequence(seq) => ExprValue::List(seq.iter().map(yaml_to_value).collect()),
        Yaml::Mapping(m) => {
            let mut out = BTreeMap::new();
            for (k, v) in m {
                if let Some(s) = k.as_str() {
                    out.insert(s.to_string(), yaml_to_value(v));
                }
            }
            ExprValue::Map(out)
        }
        Yaml::Tagged(t) => yaml_to_value(&t.value),
    }
}

pub fn yaml_mapping_to_opts(m: &Mapping) -> BTreeMap<String, ExprValue> {
    let mut out = BTreeMap::new();
    for (k, v) in m {
        if let Some(s) = k.as_str() {
            out.insert(s.to_string(), yaml_to_value(v));
        }
    }
    out
}

// ----------------------------------------------------------------------- Tests
#[cfg(test)]
mod tests {
    use super::*;
    use secator_model::{OutputItem, Port, Url};
    use secator_templates::{build_runner_tree, load_from_str};

    const HOST_RECON: &str = include_str!("../../../../secator/configs/workflows/host_recon.yaml");

    #[test]
    fn compile_workflow_produces_chain_of_tasks_and_groups() {
        let t = load_from_str(HOST_RECON).unwrap();
        let tree = build_runner_tree(&t, |_| None).unwrap();
        let plan = compile(&tree);
        let outer = match plan {
            Plan::Chain(c) => c,
            other => panic!("expected outer chain, got {other:?}"),
        };
        // The first element of host_recon is `_group` (naabu + nmap/light) → parallel.
        match &outer[0] {
            Plan::Group(g) => assert!(g.len() >= 2),
            other => panic!("expected leading group, got {other:?}"),
        }
        // Subsequent should include some Task plans.
        assert!(outer.iter().any(|p| matches!(p, Plan::Task(_))));
    }

    #[test]
    fn task_plan_extracts_target_extractors() {
        let t = load_from_str(HOST_RECON).unwrap();
        let tree = build_runner_tree(&t, |_| None).unwrap();
        let plan = compile(&tree);
        // Find a task plan by its node id (the standalone `nmap` is at `host_recon.nmap`,
        // whereas `_group/nmap/light` is at `host_recon._group.nmap/light`).
        fn find<'a>(p: &'a Plan, id: &str) -> Option<&'a TaskPlan> {
            match p {
                Plan::Task(t) if t.id == id => Some(t),
                Plan::Chain(v) | Plan::Group(v) => v.iter().find_map(|p| find(p, id)),
                _ => None,
            }
        }
        let nmap = find(&plan, "host_recon.nmap").expect("standalone nmap task plan");
        // host_recon.yaml: nmap.targets_ uses `target.name` and `port.host`.
        assert!(!nmap.target_extractors.is_empty(), "nmap should have target_extractors");
        let kinds: Vec<&str> = nmap.target_extractors.iter().map(|e| e.kind.as_str()).collect();
        assert!(kinds.contains(&"port"));
        assert!(kinds.contains(&"target"));
        // ports_ extractor goes to opt_extractors.
        assert!(nmap.opt_extractors.contains_key("ports"));
        // ancestor_id should be the workflow root.
        assert_eq!(nmap.ancestor_id.as_deref(), Some("host_recon"));
    }

    #[test]
    fn resolve_inputs_pulls_field_from_results() {
        let plan = TaskPlan {
            class: "httpx".into(),
            ancestor_defaults: std::collections::BTreeMap::new(),
            id: "host_recon.httpx".into(),
            opts: BTreeMap::new(),
            target_extractors: vec![Extractor {
                kind: "port".into(),
                field: "{host}:{port}".into(),
                condition: None,
                group_by: None,
            }],
            opt_extractors: BTreeMap::new(),
            condition: None,
            ancestor_id: None,
            description: None,
        };
        let results = vec![
            OutputItem::Port(Port {
                port: 80,
                ip: "1.1.1.1".into(),
                host: "h1".into(),
                state: "open".into(),
                ..Default::default()
            }),
            OutputItem::Port(Port {
                port: 443,
                ip: "1.1.1.1".into(),
                host: "h1".into(),
                state: "open".into(),
                ..Default::default()
            }),
            OutputItem::Url(Url { url: "https://x".into(), ..Default::default() }),
        ];
        let opts = BTreeMap::new();
        let inputs = resolve_inputs(&plan, &results, &opts, &[]);
        assert_eq!(inputs, vec!["h1:80".to_string(), "h1:443".to_string()]);
    }

    #[test]
    fn resolve_inputs_respects_condition() {
        let plan = TaskPlan {
            class: "x".into(),
            ancestor_defaults: std::collections::BTreeMap::new(),
            id: "x".into(),
            opts: BTreeMap::new(),
            target_extractors: vec![Extractor {
                kind: "port".into(),
                field: "host".into(),
                condition: Some("port.port == 22".into()),
                group_by: None,
            }],
            opt_extractors: BTreeMap::new(),
            condition: None,
            ancestor_id: None,
            description: None,
        };
        let results = vec![
            OutputItem::Port(Port { port: 22, host: "ssh-host".into(), ip: "1.1.1.1".into(), state: "open".into(), ..Default::default() }),
            OutputItem::Port(Port { port: 80, host: "web-host".into(), ip: "2.2.2.2".into(), state: "open".into(), ..Default::default() }),
        ];
        let inputs = resolve_inputs(&plan, &results, &BTreeMap::new(), &[]);
        assert_eq!(inputs, vec!["ssh-host".to_string()]);
    }

    #[test]
    fn resolve_inputs_group_by_collapses_to_one_target_per_group() {
        // Mirrors host_recon's search_vulns extractor:
        //   targets_:
        //     - type: technology
        //       field: '{match}~{product} {version}'
        //       group_by: '{product} {version}'
        // 4 Technology items, all with `nginx 1.29.8`, 4 different `match` values →
        // expect one target `<m1>,<m2>,<m3>,<m4>~nginx 1.29.8` (Python parity).
        use secator_model::Technology;
        let plan = TaskPlan {
            class: "search_vulns".into(),
            ancestor_defaults: std::collections::BTreeMap::new(),
            id: "host_recon._group_vuln.search_vulns".into(),
            opts: BTreeMap::new(),
            target_extractors: vec![Extractor {
                kind: "technology".into(),
                field: "{match}~{product} {version}".into(),
                condition: None,
                group_by: Some("{product} {version}".into()),
            }],
            opt_extractors: BTreeMap::new(),
            condition: None,
            ancestor_id: None,
            description: None,
        };
        let make_tech = |m: &str| OutputItem::Technology(Technology {
            match_: m.into(),
            product: "nginx".into(),
            version: Some("1.29.8".into()),
            ..Default::default()
        });
        let results = vec![
            make_tech("3.125.197.172:80"),
            make_tech("3.125.197.172:443"),
            make_tech("http://nginx.org:80"),
            make_tech("https://nginx.org:443"),
        ];
        let inputs = resolve_inputs(&plan, &results, &BTreeMap::new(), &[]);
        assert_eq!(inputs.len(), 1, "group_by should collapse 4 → 1");
        assert_eq!(
            inputs[0],
            "3.125.197.172:80,3.125.197.172:443,http://nginx.org:80,https://nginx.org:443~nginx 1.29.8"
        );
    }

    #[test]
    fn resolve_inputs_group_by_dedupes_within_group() {
        // Two ports on different hosts but the same product+version → only the
        // unique matches appear in the joined prefix list.
        use secator_model::Technology;
        let plan = TaskPlan {
            class: "x".into(), id: "x".into(),
            ancestor_defaults: std::collections::BTreeMap::new(),
            opts: BTreeMap::new(),
            target_extractors: vec![Extractor {
                kind: "technology".into(),
                field: "{match}~{product} {version}".into(),
                condition: None,
                group_by: Some("{product} {version}".into()),
            }],
            opt_extractors: BTreeMap::new(),
            condition: None, ancestor_id: None, description: None,
        };
        let dup = OutputItem::Technology(Technology {
            match_: "a:80".into(), product: "nginx".into(), version: Some("1.0".into()),
            ..Default::default()
        });
        let other = OutputItem::Technology(Technology {
            match_: "b:80".into(), product: "nginx".into(), version: Some("1.0".into()),
            ..Default::default()
        });
        let results = vec![dup.clone(), dup, other];
        let inputs = resolve_inputs(&plan, &results, &BTreeMap::new(), &[]);
        assert_eq!(inputs, vec!["a:80,b:80~nginx 1.0".to_string()]);
    }

    #[test]
    fn shorthand_extractor_string_parses() {
        let yaml: Yaml = serde_yaml::from_str("targets_:\n  - url.url\n").unwrap();
        let extractors_yaml = yaml.as_mapping().unwrap().get(Yaml::String("targets_".into())).unwrap();
        let extractors = parse_extractor_list(extractors_yaml);
        assert_eq!(extractors.len(), 1);
        assert_eq!(extractors[0].kind, "url");
        assert_eq!(extractors[0].field, "url");
    }

    #[test]
    fn resolve_opts_dynamic_value() {
        let mut opt_ex = BTreeMap::new();
        opt_ex.insert(
            "ports".into(),
            vec![Extractor {
                kind: "port".into(),
                field: "port".into(),
                condition: None,
                group_by: None,
            }],
        );
        let plan = TaskPlan {
            class: "x".into(), id: "x".into(),
            ancestor_defaults: std::collections::BTreeMap::new(),
            opts: BTreeMap::new(),
            target_extractors: vec![],
            opt_extractors: opt_ex,
            condition: None, ancestor_id: None, description: None,
        };
        let results = vec![
            OutputItem::Port(Port { port: 22, ip: "1".into(), host: "a".into(), state: "open".into(), ..Default::default() }),
            OutputItem::Port(Port { port: 443, ip: "1".into(), host: "a".into(), state: "open".into(), ..Default::default() }),
        ];
        let opts = resolve_opts(&plan, &results, &BTreeMap::new());
        assert_eq!(opts.get("ports"), Some(&ExprValue::Str("22,443".into())));
    }
}
