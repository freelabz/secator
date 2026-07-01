//! prompt — interactive operator gate (Python `secator/tasks/prompt.py`).
//!
//! In a TTY, asks "Validate {input}?" (y/N, default = accept) per input and
//! emits `Tag(info, name=user_input, value=<input>, match=prompt)` for the
//! accepted ones. In CI / non-TTY / when `--yes` is set, auto-accepts every
//! input (emitting with `match=auto`). For non-interactive Rust parity right
//! now, we default to **auto-accept** unconditionally — the interactive read
//! path is wired but stays behind the `secator_prompt_interactive` env var
//! until the CLI plumbs `stdin().read_line`-with-timeout properly (Python's
//! `signal.alarm` doesn't translate cleanly).

use std::io::{self, IsTerminal, Write};

use secator_model::{OutputItem, Tag};
use secator_options::{OptSchema, OptSpec, OptType, RunOpts};
use secator_runner::{HookRegistry, NativeSpec, ValidatorRegistry};

pub static SPEC: NativeSpec = NativeSpec {
    name: "prompt",
    description: "Prompt the operator (auto-accepts in CI / non-TTY).",
    input_types: &[],
    output_types: &["tag"],
    tags: &["network", "recon"],
    run,
    hooks: HookRegistry::EMPTY,
    validators: ValidatorRegistry::EMPTY,
    schema: build_schema,
    install: secator_runner::InstallSpec::EMPTY,
    proxy_caps: secator_runner::ProxyCaps::NONE,
    encoding: "utf-8",
    ignore_return_code: false,
    requires_sudo: false,
    default_inputs: Some(""),
};

fn run(inputs: &[String], opts: &RunOpts) -> Vec<OutputItem> {
    if inputs.is_empty() {
        return Vec::new();
    }
    let yes = opts
        .get("yes")
        .map(|v| matches!(v.as_str(), "true" | "1" | "yes"))
        .unwrap_or(false);
    let in_ci = is_ci();
    let template = opts
        .get("message")
        .cloned()
        .unwrap_or_else(|| "Validate {input}?".into());
    let interactive_env = std::env::var("SECATOR_PROMPT_INTERACTIVE")
        .map(|v| v != "0" && !v.is_empty())
        .unwrap_or(false);
    let force_yes = yes || in_ci || !std::io::stdin().is_terminal() || !interactive_env;

    let mut out: Vec<OutputItem> = Vec::new();
    let match_label = if force_yes { "auto" } else { "prompt" };
    for input in inputs {
        let accepted = if force_yes {
            true
        } else {
            ask_user(&template.replace("{input}", input))
        };
        if accepted {
            out.push(OutputItem::Tag(Tag {
                name: "user_input".into(),
                match_: match_label.into(),
                value: input.clone(),
                category: "info".into(),
                ..Default::default()
            }));
        }
    }
    out
}

fn is_ci() -> bool {
    [
        "CI",
        "CONTINUOUS_INTEGRATION",
        "GITHUB_ACTIONS",
        "GITLAB_CI",
        "JENKINS_URL",
        "BUILDKITE",
    ]
    .iter()
    .any(|k| std::env::var(k).map(|v| !v.is_empty()).unwrap_or(false))
}

/// Interactive y/N read with a `CONFIG.runners.prompt_timeout`-second deadline.
/// Default is "yes" so both a bare Enter AND a timeout accept — matches
/// Python's `confirm_with_timeout(default=True, timeout=CONFIG.runners.prompt_timeout)`.
///
/// The read runs on a helper thread so the timeout can fire without leaving the
/// thread blocked on stdin forever. The thread will keep running after the
/// timeout and absorb the next line the operator types — acceptable for a
/// one-shot CLI process.
fn ask_user(message: &str) -> bool {
    let stderr = io::stderr();
    let mut h = stderr.lock();
    let _ = write!(h, "{message} [Y/n] ");
    let _ = h.flush();
    drop(h); // release before potentially blocking on the recv below

    let timeout_secs = secator_config::get().runners.prompt_timeout.max(0) as u64;
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        let mut buf = String::new();
        if io::stdin().read_line(&mut buf).is_ok() {
            let _ = tx.send(buf);
        }
    });
    let recv = if timeout_secs == 0 {
        rx.recv().ok()
    } else {
        rx.recv_timeout(std::time::Duration::from_secs(timeout_secs)).ok()
    };
    match recv {
        Some(line) => {
            let s = line.trim().to_lowercase();
            s.is_empty() || s == "y" || s == "yes"
        }
        None => true, // timeout → default accept (Python parity)
    }
}

fn build_schema() -> OptSchema {
    let mut s = OptSchema { opt_prefix: "--", ..OptSchema::default() };
    s.opts = vec![
        OptSpec {
            name: "yes",
            ty: OptType::Bool,
            short: Some("y"),
            is_flag: true,
            default: None,
            help: "Auto-accept the prompt and forward all objects",
            internal: false,
            requires_sudo: false,
            shlex: true,
            pre_process: None,
            process: None,
        },
        OptSpec {
            name: "message",
            ty: OptType::Str,
            short: None,
            is_flag: false,
            default: Some("Validate {input}?"),
            help: "Prompt message ({input} is interpolated)",
            internal: false,
            requires_sudo: false,
            shlex: true,
            pre_process: None,
            process: None,
        },
    ];
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn auto_accepts_in_ci_via_yes_flag() {
        let mut opts = BTreeMap::new();
        opts.insert("yes".into(), "true".into());
        let items = run(&["10.0.0.0/24".into(), "192.168.0.0/16".into()], &opts);
        let tags: Vec<&Tag> = items
            .iter()
            .filter_map(|i| match i { OutputItem::Tag(t) => Some(t), _ => None })
            .collect();
        assert_eq!(tags.len(), 2);
        for t in &tags {
            assert_eq!(t.name, "user_input");
            assert_eq!(t.match_, "auto");
            assert_eq!(t.category, "info");
        }
        assert_eq!(tags[0].value, "10.0.0.0/24");
        assert_eq!(tags[1].value, "192.168.0.0/16");
    }

    #[test]
    fn no_inputs_yields_nothing() {
        let items = run(&[], &BTreeMap::new());
        assert!(items.is_empty());
    }
}
