//! gf — grep-with-presets pattern matcher (Python `secator/tasks/gf.py`).
//!
//! Reads input lines from stdin (one URL/string per line). For each MATCHING
//! line (i.e. every line gf prints to stdout), emits a `Tag(category=url_pattern,
//! name=<pattern>, value=<line>, match=<line>, extra_data.source=url)`.
//!
//! The `pattern` opt is REQUIRED and is passed positionally to gf (e.g.
//! `gf xss`). Workflows use the `gf/<preset>` node-id convention to spawn one
//! gf invocation per preset.

use secator_model::{Map, OutputItem, Tag};
use secator_options::{FileMode, InputWiring, KeyMap, OptSchema, OptSpec, OptType, SingleMode};
use secator_runner::{empty_output_maps, HookCtx, HookRegistry, ValidatorRegistry};
use serde_json::Value;

use crate::TaskSpec;

pub static SPEC: TaskSpec = TaskSpec {
    name: "gf",
    description: "Wrapper around grep with named pattern presets (xss, lfi, …).",
    cmd: "gf",
    // Accepts anything text-ish; no fixed schema beyond "line per input".
    input_types: &[],
    output_types: &["tag"],
    tags: &["pattern", "scan"],
    // gf reads stdin + writes matching lines on stdout. No JSON format.
    json_flag: None,
    input_wiring: InputWiring { single: SingleMode::Pipe, file: FileMode::Pipe },
    item_loaders: &[],
    input_chunk_size: 0,
    on_json_loaded: None,
    on_regex_loaded: None,
    output_maps: empty_output_maps,
    discriminator: None,
    hooks: HOOKS,
    validators: ValidatorRegistry::EMPTY,
    schema: build_schema,
    install: secator_runner::InstallSpec {
        cmd: Some("go install -v github.com/tomnomnom/gf@latest && git clone https://github.com/1ndianl33t/Gf-Patterns $HOME/.gf || true"),
        ..secator_runner::InstallSpec::EMPTY
    },
    proxy_caps: secator_runner::ProxyCaps::NONE,
    encoding: "utf-8",
    ignore_return_code: false,
    requires_sudo: false,
};

static HOOKS: HookRegistry = HookRegistry {
    before_init: &[before_init_inject_pattern],
    on_line: &[on_line_emit_tag],
    ..HookRegistry::EMPTY
};

/// Python `opt_key_map = {'pattern': ''}` — `pattern` is passed positionally
/// to gf, not as a flag. We do that via `runner.cmd_suffix`: stash the
/// preset name there so it lands right after `gf` in the cmd.
fn before_init_inject_pattern(
    ctx: &mut HookCtx,
    runner: &mut secator_runner::CommandRunner,
) {
    if let Some(p) = runner.opts.get("pattern") {
        let p = p.trim().to_string();
        if !p.is_empty() {
            runner.cmd_suffix = format!(" {p}");
            ctx.state.insert("gf:pattern".into(), p);
        }
    }
    // Drop `pattern` from opts so it doesn't double-emit as `--pattern <x>`.
    runner.opts.remove("pattern");
}

/// Every stdout line is a match. Emit a Tag for it.
fn on_line_emit_tag(ctx: &mut HookCtx, line: &str) -> Option<String> {
    let trimmed = line.trim().to_string();
    if trimmed.is_empty() {
        return Some(line.to_string());
    }
    let pattern = ctx.state.get("gf:pattern").cloned().unwrap_or_default();
    let mut extra: Map = Map::new();
    extra.insert("source".into(), Value::String("url".into()));
    ctx.extra_results.push(OutputItem::Tag(Tag {
        category: "url_pattern".into(),
        name: pattern,
        value: trimmed.clone(),
        match_: trimmed,
        extra_data: extra,
        ..Default::default()
    }));
    // Drop the line — we already emitted a Tag for it.
    None
}

fn build_schema() -> OptSchema {
    let mut s = OptSchema { opt_prefix: "-", ..OptSchema::default() };
    s.opts = vec![OptSpec {
        name: "pattern",
        ty: OptType::Str,
        short: None,
        is_flag: false,
        default: None,
        help: "gf preset name (xss, lfi, rce, ssrf, idor, debug_logic, interestingparams, …)",
        internal: false,
        requires_sudo: false,
        shlex: true,
        pre_process: None,
        process: None,
    }];
    // Python `opt_key_map = {'pattern': ''}` — pattern is passed positionally,
    // NOT as `-pattern <value>`. We mark it not-supported in the cmd-builder
    // path; `before_init` reads it from `runner.opts` and pushes it via
    // `cmd_suffix` so the final cmd is `gf <pattern>`.
    s.key_map.insert("pattern".into(), KeyMap::NotSupported);
    // gf takes no meta opts.
    for k in [
        "header", "delay", "follow_redirect", "proxy", "rate_limit",
        "retries", "threads", "timeout", "user_agent", "method", "data",
    ] {
        s.key_map.insert(k.into(), KeyMap::NotSupported);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_tag_per_match_line() {
        let mut ctx = HookCtx::default();
        ctx.state.insert("gf:pattern".into(), "xss".into());
        on_line_emit_tag(&mut ctx, "https://example.com/?q=<script>");
        on_line_emit_tag(&mut ctx, "");
        let tags: Vec<_> = ctx
            .extra_results
            .iter()
            .filter_map(|i| match i { OutputItem::Tag(t) => Some(t), _ => None })
            .collect();
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].category, "url_pattern");
        assert_eq!(tags[0].name, "xss");
        assert_eq!(tags[0].match_, "https://example.com/?q=<script>");
    }
}
