//! urlparser — extract URL components and parameters (Python
//! `secator/tasks/urlparser.py`).
//!
//! For each input URL, emits a subset of:
//!   * `Url(url=input, tags=["computed"])` when `url` ∈ include
//!   * `Tag(info, name=url_root, value=<scheme>://<host>)` when `url_root` ∈ include (dedupe)
//!   * `Tag(info, name=url_base, value=<no-query>)` when `url_base` ∈ include (dedupe)
//!   * `Tag(info, name=url_query, value=<raw query>)` when `url_query` ∈ include
//!   * `Tag(info, name=url_param, value=<name>, extra_data={value, url})` per query param
//!
//! Default include = all of the above.

use std::collections::BTreeSet;

use secator_model::{Map, OutputItem, Tag, Url};
use secator_options::{OptSchema, OptSpec, OptType, RunOpts};
use secator_runner::{HookRegistry, NativeSpec, ValidatorRegistry};
use serde_json::Value;
use url::Url as UrlParser;

pub static SPEC: NativeSpec = NativeSpec {
    name: "urlparser",
    description: "Extract query string parameters from URLs.",
    input_types: &["url"],
    output_types: &["tag", "url"],
    tags: &["url", "params"],
    run,
    hooks: HookRegistry::EMPTY,
    validators: ValidatorRegistry::EMPTY,
    schema: build_schema,
    install: secator_runner::InstallSpec::EMPTY,
    proxy_caps: secator_runner::ProxyCaps::NONE,
    encoding: "utf-8",
    ignore_return_code: false,
    requires_sudo: false,
};

fn run(inputs: &[String], opts: &RunOpts) -> Vec<OutputItem> {
    let include = parse_include(opts);
    let want_url = include.contains("url");
    let want_root = include.contains("url_root");
    let want_base = include.contains("url_base");
    let want_query = include.contains("url_query");
    let want_param = include.contains("url_param");

    let mut out: Vec<OutputItem> = Vec::new();
    let mut seen_root: BTreeSet<String> = BTreeSet::new();
    let mut seen_base: BTreeSet<String> = BTreeSet::new();

    for input in inputs {
        if want_url {
            out.push(OutputItem::Url(Url {
                url: input.clone(),
                tags: vec!["computed".into()],
                ..Default::default()
            }));
        }
        let parsed = match UrlParser::parse(input) {
            Ok(u) => u,
            Err(_) => continue,
        };
        let scheme = parsed.scheme();
        let host = parsed.host_str().unwrap_or("");
        let port_suffix = parsed
            .port()
            .map(|p| format!(":{p}"))
            .unwrap_or_default();
        let path = parsed.path();
        let query = parsed.query().unwrap_or("");

        // url_root = <scheme>://<host>[:port]
        let root_url = format!("{scheme}://{host}{port_suffix}");
        // url_base = <scheme>://<host>[:port]<path> (no query, no fragment)
        let base_url = format!("{root_url}{path}");

        if want_root && !seen_root.contains(&root_url) {
            out.push(OutputItem::Tag(Tag {
                category: "info".into(),
                name: "url_root".into(),
                value: root_url.clone(),
                match_: base_url.clone(),
                tags: vec!["computed".into()],
                ..Default::default()
            }));
            seen_root.insert(root_url);
        }
        if want_base && !seen_base.contains(&base_url) {
            out.push(OutputItem::Tag(Tag {
                category: "info".into(),
                name: "url_base".into(),
                value: base_url.clone(),
                match_: base_url.clone(),
                tags: vec!["computed".into()],
                ..Default::default()
            }));
            seen_base.insert(base_url.clone());
        }
        if want_query {
            out.push(OutputItem::Tag(Tag {
                category: "info".into(),
                name: "url_query".into(),
                value: query.to_string(),
                match_: base_url.clone(),
                tags: vec!["computed".into()],
                ..Default::default()
            }));
        }
        if want_param {
            // Group multiple values per param: Python uses parse_qs which keeps a
            // list per key and emits only the first. We do the same — pick the
            // first occurrence of each key.
            let mut seen_keys: BTreeSet<String> = BTreeSet::new();
            for (k, v) in parsed.query_pairs() {
                let k = k.into_owned();
                let v = v.into_owned();
                if !seen_keys.insert(k.clone()) {
                    continue;
                }
                let mut extra: Map = Map::new();
                extra.insert("value".into(), Value::String(v));
                extra.insert("url".into(), Value::String(input.clone()));
                out.push(OutputItem::Tag(Tag {
                    category: "info".into(),
                    name: "url_param".into(),
                    value: k,
                    match_: base_url.clone(),
                    extra_data: extra,
                    tags: vec!["computed".into()],
                    ..Default::default()
                }));
            }
        }
    }
    out
}

/// `include` is a list opt; the CLI passes it as a comma-separated string.
fn parse_include(opts: &RunOpts) -> BTreeSet<String> {
    let raw = opts.get("include").cloned().unwrap_or_default();
    if raw.is_empty() {
        return ["url", "url_root", "url_base", "url_query", "url_param"]
            .into_iter()
            .map(String::from)
            .collect();
    }
    raw.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
}

fn build_schema() -> OptSchema {
    let mut s = OptSchema { opt_prefix: "--", ..OptSchema::default() };
    s.opts = vec![OptSpec {
        name: "include",
        ty: OptType::Str,
        short: None,
        is_flag: false,
        default: Some("url,url_root,url_base,url_query,url_param"),
        help: "Comma-separated parts to include (url, url_root, url_base, url_query, url_param)",
        internal: false,
        requires_sudo: false,
        shlex: true,
        pre_process: None,
        process: None,
    }];
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn run_default(input: &str) -> Vec<OutputItem> {
        run(&[input.into()], &BTreeMap::new())
    }

    #[test]
    fn emits_url_and_components_for_simple_url() {
        let items = run_default("https://example.com/path?q=1&p=2");
        let has_url = items.iter().any(|i| matches!(i, OutputItem::Url(u) if u.url == "https://example.com/path?q=1&p=2"));
        let has_root = items.iter().any(|i| matches!(i, OutputItem::Tag(t) if t.name == "url_root" && t.value == "https://example.com"));
        let has_base = items.iter().any(|i| matches!(i, OutputItem::Tag(t) if t.name == "url_base" && t.value == "https://example.com/path"));
        let has_query = items.iter().any(|i| matches!(i, OutputItem::Tag(t) if t.name == "url_query" && t.value == "q=1&p=2"));
        let params: Vec<&Tag> = items
            .iter()
            .filter_map(|i| match i { OutputItem::Tag(t) if t.name == "url_param" => Some(t), _ => None })
            .collect();
        assert!(has_url, "missing Url, got: {items:#?}");
        assert!(has_root);
        assert!(has_base);
        assert!(has_query);
        assert_eq!(params.len(), 2);
        assert_eq!(params[0].value, "q");
        assert_eq!(params[1].value, "p");
        assert_eq!(params[0].extra_data.get("value").and_then(|v| v.as_str()), Some("1"));
    }

    #[test]
    fn dedupes_root_and_base_across_inputs() {
        let items = run(
            &[
                "https://example.com/a?x=1".into(),
                "https://example.com/a?y=2".into(),
            ],
            &BTreeMap::new(),
        );
        let bases: Vec<&Tag> = items
            .iter()
            .filter_map(|i| match i { OutputItem::Tag(t) if t.name == "url_base" => Some(t), _ => None })
            .collect();
        assert_eq!(bases.len(), 1);
    }

    #[test]
    fn include_filter_drops_unselected_components() {
        let mut opts = BTreeMap::new();
        opts.insert("include".into(), "url_param".into());
        let items = run(&["https://example.com/?a=1".into()], &opts);
        let kinds: Vec<&str> = items
            .iter()
            .map(|i| match i { OutputItem::Url(_) => "url", OutputItem::Tag(t) => t.name.as_str(), _ => "other" })
            .collect();
        // Only url_param should be present.
        for k in &kinds {
            assert_eq!(*k, "url_param", "unexpected kind {k}");
        }
        assert_eq!(kinds.len(), 1);
    }
}
