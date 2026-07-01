//! getasn — fetch ASN information for IP/host (Python `secator/tasks/getasn.py`).
//!
//! `getasn` reads one target per stdin line and prints one ASN summary per line.
//! Python emits a `Tag(category=info, name=asn, match=self.inputs[0],
//! value=line.strip())` and dedupes against `self_results`. We mirror that:
//! stash the first input in `ctx.state` during `before_init`, then emit a Tag
//! per stdout line — drop the line so it doesn't double-print.

use std::collections::BTreeSet;

use secator_model::{OutputItem, Tag};
use secator_options::{FileMode, InputWiring, KeyMap, OptSchema, SingleMode, ValueMap};
use secator_runner::{empty_output_maps, CommandRunner, HookCtx, HookRegistry, ValidatorRegistry};

use crate::meta_opts;
use crate::TaskSpec;

pub static SPEC: TaskSpec = TaskSpec {
    name: "getasn",
    description: "Get ASN information from IP address.",
    cmd: "getasn",
    input_types: &["ip", "host"],
    output_types: &["tag"],
    tags: &["ip", "probe"],
    json_flag: None,
    // Python `input_flag = OPT_PIPE_INPUT` + `file_flag = None` ⇒ everything goes
    // through stdin (single input piped, multi-input file unsupported).
    input_wiring: InputWiring { single: SingleMode::Pipe, file: FileMode::Pipe },
    // Python `item_loader` is the default str-passthrough — we handle each stdout
    // line directly in `on_line`.
    item_loaders: &[],
    // Python `input_chunk_size = 1` — one target per subprocess.
    input_chunk_size: 1,
    on_json_loaded: None,
    on_regex_loaded: None,
    output_maps: empty_output_maps,
    discriminator: None,
    hooks: HOOKS,
    validators: ValidatorRegistry::EMPTY,
    schema: build_schema,
    install: secator_runner::InstallSpec {
        version: Some("v1.0.0"),
        cmd: Some("go install github.com/freelabz/getasn@[install_version]"),
        github_handle: Some("freelabz/getasn"),
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps::NONE,
    encoding: "utf-8",
    ignore_return_code: false,
    requires_sudo: false,
    default_inputs: None,
};

static HOOKS: HookRegistry = HookRegistry {
    before_init: &[before_init_capture_input],
    on_line: &[on_line_emit_tag],
    ..HookRegistry::EMPTY
};

/// Stash the target the run is for so `on_line` can fill `Tag.match_`.
fn before_init_capture_input(ctx: &mut HookCtx, runner: &mut CommandRunner) {
    if let Some(first) = runner.inputs.first() {
        ctx.state.insert("getasn:target".into(), first.clone());
    }
}

/// Each stdout line is an ASN record. Emit a `Tag(info/asn)`, dedupe against
/// previously-emitted values for this run via `ctx.state["getasn:seen"]`, and
/// drop the line so it isn't printed verbatim.
fn on_line_emit_tag(ctx: &mut HookCtx, line: &str) -> Option<String> {
    let value = line.trim().to_string();
    if value.is_empty() {
        return None;
    }
    // Dedupe — Python's `if tag not in self.self_results: yield tag` is keyed on
    // the Tag's compare_key, which is (name, value, match_). Same target +
    // same value collapses to one tag.
    let key = format!("getasn:seen:{value}");
    if ctx.state.contains_key(&key) {
        return None;
    }
    ctx.state.insert(key, "1".into());
    // Track all seen values too, useful for tests.
    let seen = ctx.state.entry("getasn:seen".into()).or_default();
    if seen.is_empty() {
        *seen = value.clone();
    } else {
        seen.push('\n');
        seen.push_str(&value);
    }
    let target = ctx.state.get("getasn:target").cloned().unwrap_or_default();
    ctx.extra_results.push(OutputItem::Tag(Tag {
        category: "info".into(),
        name: "asn".into(),
        match_: target,
        value,
        ..Default::default()
    }));
    None
}

fn build_schema() -> OptSchema {
    let mut s = OptSchema { opt_prefix: "-", ..OptSchema::default() };
    // Python `opts = {}` — task-level. Meta opts: Python `opt_key_map` is all
    // commented out, so canonical recon flags would be passed straight through.
    // `getasn` is a thin Go wrapper that doesn't accept any of them; mark them
    // unsupported to avoid leaking `-rate-limit 50` etc. into the command.
    s.meta_opts = meta_opts::opts_recon();
    meta_opts::apply_config_defaults(&mut s.meta_opts);
    for k in [
        "header", "delay", "follow_redirect", "proxy", "rate_limit",
        "retries", "threads", "timeout", "user_agent", "method", "data",
    ] {
        s.key_map.insert(k.into(), KeyMap::NotSupported);
    }
    // Python `opt_value_map[DELAY] = lambda x: str(x) + 's' if x else None`. We
    // keep the transform for future-proofing — if the binary ever grows a
    // `--delay` flag we won't need a code change.
    s.value_map.insert("delay".into(), ValueMap::Func(delay_to_s));
    s
}

fn delay_to_s(v: &str) -> Option<String> {
    let t = v.trim();
    if t.is_empty() || t == "0" {
        None
    } else {
        Some(format!("{t}s"))
    }
}

/// Dummy use to silence the `BTreeSet` unused import while keeping it ready for
/// future loaders that need set-based dedupe.
const _: fn() -> BTreeSet<String> = BTreeSet::new;

#[cfg(test)]
mod tests {
    use super::*;

    fn run(target: &str, lines: &[&str]) -> Vec<OutputItem> {
        let mut runner = CommandRunner::new(&SPEC, vec![target.into()]);
        let mut ctx = HookCtx::default();
        before_init_capture_input(&mut ctx, &mut runner);
        for l in lines {
            on_line_emit_tag(&mut ctx, l);
        }
        ctx.extra_results
    }

    #[test]
    fn emits_tag_per_unique_line() {
        let items = run("8.8.8.8", &["AS15169 GOOGLE, US", "  AS15169 GOOGLE, US  ", "AS13335 CLOUDFLARENET, US"]);
        let tags: Vec<&Tag> = items
            .iter()
            .filter_map(|i| match i { OutputItem::Tag(t) => Some(t), _ => None })
            .collect();
        assert_eq!(tags.len(), 2);
        for t in &tags {
            assert_eq!(t.category, "info");
            assert_eq!(t.name, "asn");
            assert_eq!(t.match_, "8.8.8.8");
        }
        assert_eq!(tags[0].value, "AS15169 GOOGLE, US");
        assert_eq!(tags[1].value, "AS13335 CLOUDFLARENET, US");
    }

    #[test]
    fn drops_blank_lines() {
        let items = run("1.1.1.1", &["", "   "]);
        assert!(items.is_empty());
    }
}
