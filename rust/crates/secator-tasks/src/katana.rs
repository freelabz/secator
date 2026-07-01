//! katana — next-gen crawler / spider (Python `secator/tasks/katana.py`).
//!
//! katana emits one JSONL record per crawled endpoint. Each record nests
//! `request: {endpoint, method, ...}` and `response: {status_code, headers,
//! technologies, forms, stored_response_path, ...}`. `on_json_loaded` mirrors
//! Python: emit one `Url` for the endpoint, one `Tag(category=info, name=form)`
//! per discovered form, one `Url` per form's `action`, one
//! `Tag(category=info, name=url_param)` per query-string parameter, and one
//! `Technology` per entry in `response.technologies` (deduped per host).
//!
//! Deferred from Python:
//!   * `on_item` swaps the first/last lines of the stored-response file (a
//!     katana-specific cleanup); not needed unless the user inspects raw HTTP.
//!   * `on_end` deletes the `index.txt` file katana writes when
//!     `store_responses=true`.

use secator_model::{Map, OutputItem, Tag, Url};
use secator_options::{FileMode, InputWiring, KeyMap, OptSchema, OptSpec, OptType, SingleMode};
use secator_runner::{empty_output_maps, HookCtx, HookRegistry, ItemLoader, ValidatorRegistry};
use serde_json::Value;
use url::Url as UrlParser;

use crate::http_utils::get_techs;
use crate::meta_opts;
use crate::TaskSpec;

const EXCLUDED_PARAMS: &[&str] = &["v"];

pub static SPEC: TaskSpec = TaskSpec {
    name: "katana",
    description: "Next-generation crawling and spidering framework.",
    cmd: "katana",
    input_types: &["url", "host", "host_port", "ip"],
    output_types: &["url", "tag", "technology"],
    tags: &["url", "crawl"],
    json_flag: Some("-jsonl"),
    input_wiring: InputWiring { single: SingleMode::Flag("-u"), file: FileMode::Flag("-list") },
    item_loaders: &[ItemLoader::Json],
    input_chunk_size: 0,
    on_json_loaded: Some(on_json_loaded),
    on_regex_loaded: None,
    output_maps: empty_output_maps,
    discriminator: None,
    hooks: HOOKS,
    validators: ValidatorRegistry::EMPTY,
    schema: build_schema,
    install: secator_runner::InstallSpec {
        version: Some("v1.3.0"),
        cmd: Some("go install -v github.com/projectdiscovery/katana/cmd/katana@[install_version]"),
        github_handle: Some("projectdiscovery/katana"),
        pre: &[("apk", &["libc6-compat"])],
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps::HTTP_AND_SOCKS5,
    encoding: "utf-8",
    ignore_return_code: false,
    requires_sudo: false,
    default_inputs: None,
};

static HOOKS: HookRegistry = HookRegistry {
    on_cmd: &[on_cmd_inject_srd],
    ..HookRegistry::EMPTY
};

/// Python `on_init` for katana: when `form_fill` / `form_extraction` /
/// `store_responses` is set, append `-srd <reports_folder>/.outputs` so katana
/// writes raw responses there.
fn on_cmd_inject_srd(ctx: &mut HookCtx, cmd: &mut String) {
    let needs_srd = has_flag(cmd, "-aff")     // form_fill (renamed by key_map)
        || has_flag(cmd, "-fx")               // form_extraction
        || has_flag(cmd, "-sr");              // store_responses (renamed by key_map)
    if !needs_srd {
        return;
    }
    let reports = ctx.state.get("reports_folder").cloned().unwrap_or_default();
    let dir = if reports.is_empty() {
        "/tmp".to_string()
    } else {
        format!("{reports}/.outputs")
    };
    let _ = std::fs::create_dir_all(&dir);
    cmd.push_str(&format!(" -srd {}", shell_words::quote(&dir)));
}

fn has_flag(cmd: &str, flag: &str) -> bool {
    cmd.split_whitespace().any(|t| t == flag)
}

/// Mirrors `tasks/katana.py::on_json_loaded`. See module doc for the emitted
/// item shapes.
pub fn on_json_loaded(ctx: &mut HookCtx, item: Map) -> Vec<OutputItem> {
    let request = item.get("request").and_then(|v| v.as_object()).cloned().unwrap_or_default();
    let response = item.get("response").and_then(|v| v.as_object()).cloned();
    let endpoint = string_field(&request, "endpoint");
    if endpoint.is_empty() {
        return Vec::new();
    }
    let parsed = match UrlParser::parse(&endpoint) {
        Ok(u) => u,
        Err(_) => return Vec::new(),
    };
    let host = parsed.host_str().unwrap_or("").to_string();
    let url_without_params = {
        let mut u = parsed.clone();
        u.set_query(None);
        u.to_string()
    };
    let params: Vec<String> =
        parsed.query().unwrap_or("").split('&').map(String::from).collect();

    let mut out: Vec<OutputItem> = Vec::new();
    let headless = ctx.state.get("katana:headless").map(|s| s == "1").unwrap_or(false);
    let tags = if headless { vec!["headless".into()] } else { Vec::new() };

    if response.is_none() {
        return out;
    }
    let response = response.unwrap();
    let stored_path = string_field(&response, "stored_response_path");

    // Forms → one Url + one form Tag each.
    if let Some(forms) = response.get("forms").and_then(|v| v.as_array()) {
        for form in forms {
            let action = form
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let method = form
                .get("method")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if action.is_empty() {
                continue;
            }
            out.push(OutputItem::Url(Url {
                url: action.clone(),
                host: host.clone(),
                method: method.clone(),
                stored_response_path: stored_path.clone(),
                ..Default::default()
            }));
            let form_params = form.get("parameters").cloned().unwrap_or(Value::Array(Vec::new()));
            let enctype = form.get("enctype").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let mut form_extra = Map::new();
            form_extra.insert("method".into(), Value::String(method));
            form_extra.insert("enctype".into(), Value::String(enctype));
            form_extra.insert("parameters".into(), form_params);
            out.push(OutputItem::Tag(Tag {
                category: "info".into(),
                name: "form".into(),
                value: action.clone(),
                match_: action,
                stored_response_path: stored_path.clone(),
                extra_data: form_extra,
                ..Default::default()
            }));
        }
    }

    // Primary URL.
    let techs_arr = response
        .get("technologies")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect::<Vec<_>>())
        .unwrap_or_default();
    let status_code = response.get("status_code").and_then(|v| v.as_i64()).unwrap_or(0);
    let content_length = response.get("content_length").and_then(|v| v.as_i64()).unwrap_or(0);
    let resp_headers = response
        .get("headers")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let url = Url {
        url: endpoint.clone(),
        host: host.clone(),
        method: string_field(&request, "method"),
        time: string_field_value(&item, "timestamp"),
        status_code,
        content_length,
        tech: techs_arr,
        stored_response_path: stored_path.clone(),
        response_headers: resp_headers,
        tags,
        ..Default::default()
    };

    // Technologies — dedup per host using ctx.state so repeated crawls of the
    // same domain don't spam the operator with the same Nginx/HSTS line.
    for tech in get_techs(&url) {
        let key = format!(
            "katana:tech:{host}|{}|{}",
            tech.product,
            tech.version.clone().unwrap_or_default()
        );
        if ctx.state.contains_key(&key) {
            continue;
        }
        ctx.state.insert(key, "1".into());
        out.push(OutputItem::Technology(tech));
    }
    out.push(OutputItem::Url(url));

    // URL params → one Tag each (skipping EXCLUDED_PARAMS like `v`).
    for raw in &params {
        if raw.is_empty() {
            continue;
        }
        let mut parts = raw.splitn(2, '=');
        let name = parts.next().unwrap_or("");
        if name.is_empty() || EXCLUDED_PARAMS.contains(&name) {
            continue;
        }
        let value = parts.next().unwrap_or("");
        let mut extra = Map::new();
        extra.insert("value".into(), Value::String(value.to_string()));
        extra.insert("url".into(), Value::String(endpoint.clone()));
        out.push(OutputItem::Tag(Tag {
            category: "info".into(),
            name: "url_param".into(),
            value: name.to_string(),
            match_: url_without_params.clone(),
            extra_data: extra,
            ..Default::default()
        }));
    }

    out
}

fn string_field(m: &Map, key: &str) -> String {
    m.get(key).and_then(|v| v.as_str()).unwrap_or("").to_string()
}
fn string_field_value(m: &Map, key: &str) -> String {
    m.get(key).and_then(|v| v.as_str()).unwrap_or("").to_string()
}

/// Python `opts` + `opt_key_map`. HttpCrawler base + the long list of katana
/// `-flag`s. Most filter/match meta-opts are `NOT_SUPPORTED` here (katana
/// doesn't have those flags).
fn build_schema() -> OptSchema {
    let mut s = OptSchema::default();
    s.meta_opts = meta_opts::opts_http_base();
    meta_opts::apply_config_defaults(&mut s.meta_opts);
    // Python key_map: most filter/match/method opts → NOT_SUPPORTED.
    for k in [
        "method", "follow_redirect", "user_agent", "filter_codes", "filter_regex",
        "filter_size", "filter_words", "match_codes", "match_regex", "match_size",
        "match_words",
    ] {
        s.key_map.insert(k.into(), KeyMap::NotSupported);
    }
    s.key_map.insert("header".into(), KeyMap::Flag("headers".into()));
    s.key_map.insert("delay".into(), KeyMap::Flag("delay".into()));
    s.key_map.insert("depth".into(), KeyMap::Flag("depth".into()));
    s.key_map.insert("proxy".into(), KeyMap::Flag("proxy".into()));
    s.key_map.insert("rate_limit".into(), KeyMap::Flag("rate-limit".into()));
    s.key_map.insert("retries".into(), KeyMap::Flag("retry".into()));
    s.key_map.insert("threads".into(), KeyMap::Flag("concurrency".into()));
    s.key_map.insert("timeout".into(), KeyMap::Flag("timeout".into()));
    s.opts = vec![
        flag("headless", Some("hl"), "Headless mode"),
        flag("system_chrome", Some("sc"), "Use local installed Chrome"),
        flag("form_extraction", Some("fx"), "Detect forms (writes to -srd)"),
        flag_default(
            "store_responses",
            "sr",
            "Save HTTP responses to disk",
            secator_config::get().http.store_responses,
        ),
        flag("form_fill", Some("ff"), "Enable form filling"),
        flag("js_crawl", Some("jc"), "Crawl endpoints inside JavaScript files"),
        flag("jsluice", Some("jsl"), "Use jsluice for JS parsing (memory-heavy)"),
        str_opt("known_files", Some("kf"), "Known files: all, robotstxt, sitemapxml"),
        flag_default("omit_raw", "or", "Omit raw req/resp from jsonl", true),
        flag_default("omit_body", "ob", "Omit response body from jsonl", true),
        flag("no_sandbox", Some("ns"), "Disable Chromium sandboxing"),
    ];
    // Python opt_key_map renames: store_responses → sr, form_fill → aff.
    s.key_map.insert("store_responses".into(), KeyMap::Flag("sr".into()));
    s.key_map.insert("form_fill".into(), KeyMap::Flag("aff".into()));
    s
}

const fn str_opt(name: &'static str, short: Option<&'static str>, help: &'static str) -> OptSpec {
    OptSpec {
        name, ty: OptType::Str, short, is_flag: false, default: None,
        help, internal: false, requires_sudo: false, shlex: true,
        pre_process: None, process: None,
    }
}
const fn flag(name: &'static str, short: Option<&'static str>, help: &'static str) -> OptSpec {
    OptSpec {
        name, ty: OptType::Bool, short, is_flag: true, default: None,
        help, internal: false, requires_sudo: false, shlex: true,
        pre_process: None, process: None,
    }
}
fn flag_default(name: &'static str, short: &'static str, help: &'static str, on: bool) -> OptSpec {
    let mut o = flag(name, Some(short), help);
    if on {
        o.default = Some("true");
    }
    o
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
    fn emits_url_with_techs() {
        let mut ctx = HookCtx::default();
        let line = r#"{
          "timestamp":"2024-08-14T12:00:00Z",
          "request":{"endpoint":"https://example.com/a?b=1&v=hide","method":"GET"},
          "response":{"status_code":200,"content_length":100,"technologies":["Nginx:1.18.0","HSTS"],"headers":{}}
        }"#;
        let items = run(line, &mut ctx);
        // Expected: 1 Technology (Nginx) + 1 Technology (HSTS) + 1 Url + 1 Tag (url_param `b`).
        // The `v` param is excluded.
        let n_url = items.iter().filter(|i| matches!(i, OutputItem::Url(_))).count();
        let n_tech = items.iter().filter(|i| matches!(i, OutputItem::Technology(_))).count();
        let n_tag = items.iter().filter(|i| matches!(i, OutputItem::Tag(_))).count();
        assert_eq!(n_url, 1);
        assert_eq!(n_tech, 2);
        assert_eq!(n_tag, 1);
        let tag = items.iter().find_map(|i| match i { OutputItem::Tag(t) => Some(t), _ => None }).unwrap();
        assert_eq!(tag.name, "url_param");
        assert_eq!(tag.value, "b");
    }

    #[test]
    fn dedupes_technologies_per_host() {
        let mut ctx = HookCtx::default();
        let line = r#"{"request":{"endpoint":"https://a.com/p1"},"response":{"technologies":["Nginx:1.0"]}}"#;
        let first = run(line, &mut ctx);
        let second = run(line, &mut ctx);
        let t1 = first.iter().filter(|i| matches!(i, OutputItem::Technology(_))).count();
        let t2 = second.iter().filter(|i| matches!(i, OutputItem::Technology(_))).count();
        assert_eq!(t1, 1);
        assert_eq!(t2, 0, "same host+tech dedupes on subsequent records");
    }

    #[test]
    fn form_emits_url_and_form_tag() {
        let mut ctx = HookCtx::default();
        let line = r#"{"request":{"endpoint":"https://x"},"response":{"forms":[{"action":"https://x/login","method":"POST","parameters":["user","pass"]}]}}"#;
        let items = run(line, &mut ctx);
        let n_form = items.iter().filter(|i| match i { OutputItem::Tag(t) => t.name == "form", _ => false }).count();
        assert_eq!(n_form, 1);
        let action_url = items.iter().find_map(|i| match i {
            OutputItem::Url(u) if u.url == "https://x/login" => Some(u), _ => None
        }).expect("form action emitted as Url");
        assert_eq!(action_url.method, "POST");
    }
}
