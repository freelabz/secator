//! searchsploit — ExploitDB CLI lookup (Python `secator/tasks/searchsploit.py`).
//!
//! `searchsploit --json` emits one JSON dict per exploit on its own line; the
//! wrapper `{SEARCH, RESULTS_EXPLOIT: [...]}` brackets are on separate lines and
//! don't form a parseable single-line object, so the JSON loader naturally only
//! latches onto the per-exploit dicts. Targets may use the `matched_at~query`
//! shape (same convention as `search_vulns`); `before_init` splits on `~` and
//! stashes the matched_at side in `ctx.state` for `on_json_loaded`.

use secator_model::{Exploit, Info, Map, OutputItem};
use secator_options::{
    FileMode, InputWiring, KeyMap, OptSchema, OptSpec, OptType, SingleMode,
};
use secator_runner::{
    empty_output_maps, CommandRunner, HookCtx, HookRegistry, ItemLoader, ValidatorRegistry,
};
use serde_json::Value;

use crate::TaskSpec;

pub static SPEC: TaskSpec = TaskSpec {
    name: "searchsploit",
    description: "Exploit searcher based on ExploitDB (CLI).",
    cmd: "searchsploit",
    input_types: &["string", "slug"],
    output_types: &["exploit"],
    tags: &["exploit", "recon"],
    json_flag: Some("--json"),
    // Python `input_chunk_size = 1` + positional input.
    input_wiring: InputWiring { single: SingleMode::Arg, file: FileMode::Unsupported },
    item_loaders: &[ItemLoader::Json],
    input_chunk_size: 1,
    on_json_loaded: Some(on_json_loaded),
    on_regex_loaded: None,
    output_maps: empty_output_maps,
    discriminator: None,
    hooks: HOOKS,
    validators: ValidatorRegistry::EMPTY,
    schema: build_schema,
    install: secator_runner::InstallSpec {
        version: Some("2025-04-23"),
        cmd: Some("git clone --depth 1 --single-branch -b [install_version] https://gitlab.com/exploit-database/exploitdb.git $HOME/.local/share/exploitdb_[install_version] || true && ln -sf $HOME/.local/share/exploitdb_[install_version]/searchsploit $HOME/.local/bin/searchsploit"),
        pre: &[("apk", &["ncurses"])],
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps::NONE,
    encoding: "utf-8",
    ignore_return_code: false,
    requires_sudo: false,
};

static HOOKS: HookRegistry = HookRegistry {
    before_init: &[before_init_split_matched_at],
    ..HookRegistry::EMPTY
};

/// Python `tasks/searchsploit.py::before_init`. Single-input mode only. If the
/// input has a `~`, split — left becomes `matched_at` (stashed in `ctx.state`),
/// right becomes the actual query. The query gets `httpd` stripped and `/` →
/// space (Python's `.replace('httpd', '').replace('/', ' ')`).
fn before_init_split_matched_at(ctx: &mut HookCtx, runner: &mut CommandRunner) {
    if runner.inputs.is_empty() {
        return;
    }
    let raw = runner.inputs[0].clone();
    let (matched_at, mut query) = match raw.split_once('~') {
        Some((m, q)) => (Some(m.to_string()), q.to_string()),
        None => (None, raw),
    };
    query = query.replace("httpd", "").replace('/', " ").trim().to_string();
    runner.inputs[0] = query.clone();
    if let Some(m) = matched_at {
        ctx.state.insert("searchsploit:matched_at".into(), m);
    }
    ctx.state.insert("searchsploit:query".into(), query);
}

/// One Exploit per (record × matched_at). The first record also emits a
/// `Info` "Targets: ..." line (Python `_targets_info_yielded` gate).
pub fn on_json_loaded(ctx: &mut HookCtx, record: Map) -> Vec<OutputItem> {
    // Skip the wrapper dict (it never has a Title, only SEARCH / RESULTS_*).
    if !record.contains_key("Title") {
        return Vec::new();
    }
    let matched_ats: Vec<String> = match ctx.state.get("searchsploit:matched_at") {
        Some(m) => m.split(',').map(|s| s.trim().to_string()).collect(),
        None => vec![ctx.state.get("searchsploit:query").cloned().unwrap_or_default()],
    };
    let mut out: Vec<OutputItem> = Vec::new();
    if !ctx.state.contains_key("searchsploit:targets_yielded") {
        ctx.state.insert("searchsploit:targets_yielded".into(), "1".into());
        out.push(OutputItem::Info(Info {
            message: format!("Targets: {}", matched_ats.join(", ")),
            ..Default::default()
        }));
    }
    let edb_id = record.get("EDB-ID").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let title = record.get("Title").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let codes = record.get("Codes").and_then(|v| v.as_str()).unwrap_or("");
    let cves: Vec<String> = codes
        .split(';')
        .map(|s| s.trim().to_string())
        .filter(|s| s.starts_with("CVE-"))
        .collect();
    let reference = if edb_id.is_empty() {
        String::new()
    } else {
        format!("https://exploit-db.com/exploits/{edb_id}")
    };
    let mut base_tags = extract_tags(&record);
    // Input tag (Python adds it in on_item).
    if let Some(q) = ctx.state.get("searchsploit:query") {
        let input_tag = q.replace('\'', "").replace(' ', "-");
        if !input_tag.is_empty() {
            base_tags.insert(0, input_tag);
        }
    }
    // Run the Python title-regex post-processing.
    let mut name_after = title.clone();
    let mut tags = base_tags.clone();
    if let Some((product, versions, new_title)) = title_post_process(&title) {
        name_after = new_title;
        tags.extend(
            versions
                .iter()
                .map(|v| format!("{} {}", product.to_lowercase(), v.trim())),
        );
    }
    let extra_data = extract_extra_data(&record, ctx);
    for matched_at in &matched_ats {
        out.push(OutputItem::Exploit(Exploit {
            name: name_after.clone(),
            id: edb_id.clone(),
            provider: "EDB".into(),
            matched_at: matched_at.clone(),
            confidence: "high".into(),
            reference: reference.clone(),
            cves: cves.clone(),
            tags: tags.clone(),
            extra_data: extra_data.clone(),
            ..Default::default()
        }));
    }
    out
}

/// Python `tags_extractor`. Comma-split the `Tags` field, drop empties.
fn extract_tags(item: &Map) -> Vec<String> {
    item.get("Tags")
        .and_then(|v| v.as_str())
        .map(|s| {
            s.split(',')
                .map(|t| t.trim())
                .filter(|t| !t.is_empty())
                .map(String::from)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

/// Python `output_map[Exploit][EXTRA_DATA]`: every field except the well-known
/// ones; keys are lowercased and `date_` prefix is stripped. Skips empty values.
fn extract_extra_data(item: &Map, ctx: &HookCtx) -> Map {
    let drop: [&str; 4] = ["Title", "EDB-ID", "Codes", "Tags"];
    let mut out = Map::new();
    for (k, v) in item {
        if drop.contains(&k.as_str()) {
            continue;
        }
        if let Value::String(s) = v {
            if s.is_empty() {
                continue;
            }
        }
        let key = k.to_lowercase().replace("date_", "");
        out.insert(key, v.clone());
    }
    if let Some(q) = ctx.state.get("searchsploit:query") {
        out.insert("service_name".into(), Value::String(q.clone()));
    }
    if let Some(m) = ctx.state.get("searchsploit:matched_at") {
        out.insert("matched_at".into(), Value::String(m.clone()));
    }
    out
}

/// Python `SEARCHSPLOIT_TITLE_REGEX` (`^((?:[a-zA-Z\-_!\.()]+\d?\s?)+)\.?\s*(.*)$`).
/// Returns `(product, version_list, new_title)` when the regex matches; otherwise
/// `None`. The product is the leading alphanum block; the trailing portion is
/// `<versions> - <title>` (versions joined by `/`).
fn title_post_process(title: &str) -> Option<(String, Vec<String>, String)> {
    use regex::Regex;
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"^((?:[a-zA-Z\-_!\.()]+\d?\s?)+)\.?\s*(.*)$").unwrap()
    });
    let caps = re.captures(title)?;
    let product = caps.get(1)?.as_str().trim();
    let rest = caps.get(2)?.as_str();
    if rest.len() <= 1 {
        return None;
    }
    let mut parts = rest.splitn(2, " - ");
    let versions_str = parts.next().unwrap_or("");
    let new_title = parts.next().unwrap_or(title).to_string();
    let versions: Vec<String> = versions_str
        .split('/')
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .collect();
    Some((product.replace(' ', "-"), versions, new_title))
}

fn build_schema() -> OptSchema {
    let mut s = OptSchema { opt_prefix: "--", ..OptSchema::default() };
    s.opts = vec![flag("strict", Some("s"), "Strict match")];
    s.key_map.insert("strict".into(), KeyMap::Flag("-s".into()));
    s
}

const fn flag(name: &'static str, short: Option<&'static str>, help: &'static str) -> OptSpec {
    OptSpec {
        name, ty: OptType::Bool, short, is_flag: true, default: None,
        help, internal: false, requires_sudo: false, shlex: true,
        pre_process: None, process: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secator_parse::{JsonSerializer, Serializer};

    fn run(line: &str, ctx: &mut HookCtx) -> Vec<OutputItem> {
        JsonSerializer::new()
            .run(line)
            .into_iter()
            .flat_map(|r| on_json_loaded(ctx, r))
            .collect()
    }

    #[test]
    fn parses_per_line_exploit_record() {
        let mut ctx = HookCtx::default();
        ctx.state.insert("searchsploit:query".into(), "wordpress".into());
        let line = r#"{"Title":"Flexpaper PHP Publish Service 2.3.6 - Remote Code Execution","EDB-ID":"46528","Codes":"CVE-2018-11686;CVE-2018-9999","Tags":"webapps,rce","Date_Published":"2019-03-11"}"#;
        let items = run(line, &mut ctx);
        // Expect 1 Info ("Targets:") + 1 Exploit.
        let exploits: Vec<_> = items.iter().filter_map(|i| match i { OutputItem::Exploit(e) => Some(e), _ => None }).collect();
        assert_eq!(exploits.len(), 1);
        let e = exploits[0];
        assert_eq!(e.id, "46528");
        assert_eq!(e.provider, "EDB");
        assert_eq!(e.cves, vec!["CVE-2018-11686".to_string(), "CVE-2018-9999".to_string()]);
        assert!(e.reference.ends_with("/46528"));
        assert!(e.tags.contains(&"wordpress".to_string()));
        // Title post-process should have moved versions to tags.
        assert!(e.tags.iter().any(|t| t.contains("flexpaper")));
    }

    #[test]
    fn skips_wrapper_dict_without_title() {
        let mut ctx = HookCtx::default();
        ctx.state.insert("searchsploit:query".into(), "nginx".into());
        // The outer wrapper has SEARCH/RESULTS_*, no Title.
        let items = run(r#"{"SEARCH":"nginx","RESULTS_EXPLOIT":[]}"#, &mut ctx);
        assert!(items.iter().all(|i| !matches!(i, OutputItem::Exploit(_))));
    }

    #[test]
    fn before_init_splits_tilde_and_normalizes() {
        let mut ctx = HookCtx::default();
        let mut runner = CommandRunner::new(&SPEC, vec!["host:443~apache/httpd 2.4".into()]);
        before_init_split_matched_at(&mut ctx, &mut runner);
        // `httpd` stripped, `/` → space, trimmed.
        assert_eq!(runner.inputs[0], "apache  2.4");
        assert_eq!(ctx.state.get("searchsploit:matched_at"), Some(&"host:443".to_string()));
    }
}
