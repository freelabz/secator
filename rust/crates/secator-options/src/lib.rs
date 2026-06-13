//! Option schema, resolution, and command-string assembly.
//!
//! Maps to the option engine in Python `secator/runners/command.py`
//! (`_process_opts`/`_get_opt_value`/`_build_cmd`/`_build_cmd_input`). See
//! `../docs/rewrite/04-task-integration.md` §3 and ADR-0006.

use std::collections::BTreeMap;

/// Load-bearing sentinels (Python `definitions.py`). Encoded as `MapValue::Sentinel` to
/// avoid clashing with real string/int values.
pub const SENTINEL_NOT_SUPPORTED: &str = "__OPT_NOT_SUPPORTED__";
pub const SENTINEL_PIPE_INPUT: &str = "__OPT_PIPE_INPUT__";
pub const SENTINEL_SPACE_SEPARATED: &str = "__OPT_SPACE_SEPARATED__";

/// Declared type of an option value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OptType {
    Str,
    Int,
    Float,
    List,
    Bool,
    Choice(Vec<String>),
}

/// Closure-shaped transform applied to an option value.
pub type Transform = fn(&str) -> Option<String>;

/// A single option definition (Python `opt_conf`).
#[derive(Clone)]
pub struct OptSpec {
    pub name: &'static str,
    pub ty: OptType,
    pub short: Option<&'static str>,
    pub is_flag: bool,
    pub default: Option<&'static str>,
    pub help: &'static str,
    /// Resolved but not emitted to the command line.
    pub internal: bool,
    pub requires_sudo: bool,
    /// Shell-quote the value (default true).
    pub shlex: bool,
    /// Pre-process raw value before key/value mapping.
    pub pre_process: Option<Transform>,
    /// Post-process at command-build time.
    pub process: Option<Transform>,
}
impl OptSpec {
    pub const fn flag(name: &'static str) -> Self {
        OptSpec {
            name, ty: OptType::Bool, short: None, is_flag: true, default: None,
            help: "", internal: false, requires_sudo: false, shlex: true,
            pre_process: None, process: None,
        }
    }
    pub const fn str(name: &'static str) -> Self {
        OptSpec {
            name, ty: OptType::Str, short: None, is_flag: false, default: None,
            help: "", internal: false, requires_sudo: false, shlex: true,
            pre_process: None, process: None,
        }
    }
}

/// Mapping value: a real CLI flag name, or the "drop this option" sentinel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyMap {
    Flag(String),
    NotSupported,
}

/// A value transform (constant or function).
#[derive(Clone)]
pub enum ValueMap {
    Const(String),
    Func(fn(&str) -> Option<String>),
}

/// A task's full option surface (Python `opts`/`meta_opts`/`opt_key_map`/`opt_value_map`).
#[derive(Clone)]
pub struct OptSchema {
    pub opts: Vec<OptSpec>,
    pub meta_opts: Vec<OptSpec>,
    /// Canonical opt name → actual CLI flag (or NotSupported to drop).
    pub key_map: BTreeMap<String, KeyMap>,
    pub value_map: BTreeMap<String, ValueMap>,
    /// "-" or "--".
    pub opt_prefix: &'static str,
}
impl Default for OptSchema {
    fn default() -> Self {
        OptSchema {
            opts: Vec::new(),
            meta_opts: Vec::new(),
            key_map: BTreeMap::new(),
            value_map: BTreeMap::new(),
            opt_prefix: "-",
        }
    }
}

/// User-supplied run-time options as a flat map (Python `run_opts`).
pub type RunOpts = BTreeMap<String, String>;

/// Resolve an option's value honoring aliases (`<alias>.<opt>`, `<alias>_<opt>`, name,
/// then `short`), defaults, and the unsupported sentinel (Python `_get_opt_value`).
/// Returns `None` if the option is unsupported or has no value.
pub fn resolve_value(
    opts: &RunOpts,
    spec: &OptSpec,
    schema: &OptSchema,
    aliases: &[String],
) -> Option<String> {
    // Aliased lookups
    let mut names: Vec<String> = Vec::with_capacity(aliases.len() * 2 + 2);
    for a in aliases {
        names.push(format!("{a}.{}", spec.name));
        names.push(format!("{a}_{}", spec.name));
    }
    names.push(spec.name.to_string());
    if let Some(s) = spec.short {
        names.push(s.to_string());
    }
    // Dedup preserving order.
    let mut seen = std::collections::HashSet::new();
    names.retain(|n| seen.insert(n.clone()));

    // Unsupported sentinel short-circuits.
    if names.iter().any(|n| opts.get(n).map(|v| v == SENTINEL_NOT_SUPPORTED).unwrap_or(false)) {
        return None;
    }
    // Also: if the key_map drops this opt, the engine skips entirely (handled at build).
    if matches!(schema.key_map.get(spec.name), Some(KeyMap::NotSupported)) {
        return None;
    }

    let mut value = names.iter().find_map(|n| opts.get(n).cloned());
    if value.is_none() {
        value = spec.default.map(|s| s.to_string());
    }
    let value = value?;

    // Drop falsy values (Python skips None/False/[]).
    if value.is_empty() || value == "false" || value == "False" {
        return None;
    }

    // pre_process from spec, OR value_map override.
    let final_value = if let Some(vm) = schema.value_map.get(spec.name) {
        match vm {
            ValueMap::Const(c) => Some(c.clone()),
            ValueMap::Func(f) => f(&value),
        }
    } else if let Some(pp) = spec.pre_process {
        pp(&value)
    } else {
        Some(value)
    }?;

    Some(final_value)
}

/// Assemble the full command string from a base cmd, schema, and resolved opts
/// (Python `_build_cmd` + `_build_opt_str`): key/value maps, prefixing, flag vs value,
/// list repetition, shlex quoting, `internal` skipping.
pub fn build_command(
    base_cmd: &str,
    schema: &OptSchema,
    opts: &RunOpts,
    aliases: &[String],
) -> String {
    let mut cmd = base_cmd.to_string();
    let emit = |spec: &OptSpec, value: String| {
        if spec.internal {
            return None;
        }
        // Resolve final flag name.
        let mapped_name: String = match schema.key_map.get(spec.name) {
            Some(KeyMap::NotSupported) => return None,
            Some(KeyMap::Flag(n)) => n.clone(),
            None => spec.name.to_string(),
        };
        // Apply spec.process at build time.
        let value = if let Some(p) = spec.process { p(&value)? } else { value };
        // Prefix.
        let flag = build_flag(&mapped_name, schema.opt_prefix);
        // Emit.
        if spec.is_flag {
            // Boolean flag — only the flag.
            if value == "true" || value == "1" || value == "True" {
                Some(flag)
            } else {
                None
            }
        } else {
            let v = if spec.shlex { shell_words::quote(&value).to_string() } else { value };
            Some(format!("{flag} {v}"))
        }
    };

    for spec in schema.opts.iter().chain(schema.meta_opts.iter()) {
        if let Some(value) = resolve_value(opts, spec, schema, aliases) {
            if let Some(s) = emit(spec, value) {
                cmd.push(' ');
                cmd.push_str(&s);
            }
        }
    }
    cmd
}

fn build_flag(name: &str, prefix: &str) -> String {
    // Already prefixed (e.g. mapped flag "--quiet").
    if name.starts_with('-') {
        return name.to_string();
    }
    // Empty mapping = emit value with no flag (Python `gf` pattern).
    if name.is_empty() {
        return String::new();
    }
    // Normalize underscores -> dashes.
    let normalized = name.replace('_', "-");
    format!("{prefix}{normalized}")
}

/// How a task passes its targets to the tool. Tasks declare BOTH a single-input mode
/// (Python `input_flag`) and a file-input mode (Python `file_flag`); the runner picks
/// based on `inputs.len()`. Flag strings are `&'static str` so SPECs fit in `static`.
#[derive(Debug, Clone)]
pub struct InputWiring {
    pub single: SingleMode,
    pub file: FileMode,
}
#[derive(Debug, Clone)]
pub enum SingleMode {
    /// Positional last argument: `cmd <input>`.
    Arg,
    /// `cmd <flag> <input>`. Empty flag → positional.
    Flag(&'static str),
    /// `echo <input> | cmd` (Python `OPT_PIPE_INPUT`).
    Pipe,
}
#[derive(Debug, Clone)]
pub enum FileMode {
    /// Positional last argument: `cmd <file>`.
    Arg,
    /// `cmd <flag> <file>`. Empty flag → positional.
    Flag(&'static str),
    /// `cat <file> | cmd` (Python `OPT_PIPE_INPUT`).
    Pipe,
    /// `cmd <a> <b> <c>` (Python `OPT_SPACE_SEPARATED`).
    SpaceSeparated,
    /// Task does not accept multi-input — Python `file_flag is None`. The runner
    /// detects this and chunks the input list into N single-input subprocess runs
    /// (each goes through `SingleMode`). Mirrors `break_task` in `celery.py`.
    Unsupported,
}
impl Default for SingleMode { fn default() -> Self { SingleMode::Arg } }
impl Default for FileMode { fn default() -> Self { FileMode::Arg } }
impl Default for InputWiring {
    fn default() -> Self { InputWiring { single: SingleMode::Arg, file: FileMode::Arg } }
}

/// Wire targets into the command (Python `_build_cmd_input`). 1 input → `single`; many
/// inputs → `file` (caller must have written `<file_path>`).
pub fn build_input(cmd: &str, inputs: &[String], wiring: &InputWiring, file_path: Option<&str>) -> String {
    match inputs.len() {
        0 => cmd.to_string(),
        1 => apply_single(cmd, &inputs[0], &wiring.single),
        _ => apply_file(cmd, inputs, &wiring.file, file_path),
    }
}

fn apply_single(cmd: &str, input: &str, mode: &SingleMode) -> String {
    let q = shell_words::quote(input);
    match mode {
        SingleMode::Arg => format!("{cmd} {q}"),
        SingleMode::Flag(f) if f.is_empty() => format!("{cmd} {q}"),
        SingleMode::Flag(f) => format!("{cmd} {f} {q}"),
        SingleMode::Pipe => format!("echo {q} | {cmd}"),
    }
}

fn apply_file(cmd: &str, inputs: &[String], mode: &FileMode, file_path: Option<&str>) -> String {
    let path = file_path.unwrap_or("");
    match mode {
        FileMode::Arg => format!("{cmd} {path}"),
        FileMode::Flag(f) if f.is_empty() => format!("{cmd} {path}"),
        FileMode::Flag(f) => format!("{cmd} {f} {path}"),
        FileMode::Pipe => format!("cat {path} | {cmd}"),
        FileMode::SpaceSeparated => {
            let joined = inputs.iter().map(|s| shell_words::quote(s).to_string())
                .collect::<Vec<_>>().join(" ");
            format!("{cmd} {joined}")
        }
        // `Unsupported` should never reach `build_input` — `CommandRunner::run`
        // chunks the inputs first. If it ever does (caller bypassed `run`), fall
        // back to the single-input form against the first input so we don't
        // silently emit a broken file path.
        FileMode::Unsupported => apply_single(
            cmd,
            inputs.first().map(String::as_str).unwrap_or(""),
            &SingleMode::Arg,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schema_subfinder() -> OptSchema {
        let mut s = OptSchema { opt_prefix: "-", ..OptSchema::default() };
        s.meta_opts = vec![
            OptSpec::str("rate_limit"),
            OptSpec::str("timeout"),
            OptSpec::str("threads"),
            OptSpec::str("proxy"),
            OptSpec::str("delay"),
            OptSpec::str("retries"),
        ];
        s.key_map.insert("delay".into(), KeyMap::NotSupported);
        s.key_map.insert("retries".into(), KeyMap::NotSupported);
        s.key_map.insert("rate_limit".into(), KeyMap::Flag("rate-limit".into()));
        s.key_map.insert("threads".into(), KeyMap::Flag("t".into()));
        // proxy value transform: strip scheme.
        s.value_map.insert("proxy".into(), ValueMap::Func(|v| {
            let v = v.trim_start_matches("https://").trim_start_matches("http://");
            Some(v.to_string())
        }));
        s
    }

    #[test]
    fn build_command_basic_flags_and_renames() {
        let schema = schema_subfinder();
        let mut opts = RunOpts::new();
        opts.insert("rate_limit".into(), "100".into());
        opts.insert("threads".into(), "10".into());
        opts.insert("proxy".into(), "http://127.0.0.1:8080".into());
        // delay is not supported -> dropped
        opts.insert("delay".into(), "5".into());
        let cmd = build_command("subfinder -cs", &schema, &opts, &[]);
        assert!(cmd.contains("-rate-limit 100"), "got: {cmd}");
        assert!(cmd.contains("-t 10"), "got: {cmd}");
        assert!(cmd.contains("-proxy 127.0.0.1:8080"), "got: {cmd}");
        assert!(!cmd.contains("delay"), "got: {cmd}");
        assert!(!cmd.contains("retries"), "got: {cmd}");
    }

    #[test]
    fn alias_resolution_picks_qualified_name_first() {
        let schema = schema_subfinder();
        let mut opts = RunOpts::new();
        opts.insert("recon.threads".into(), "50".into());
        let cmd = build_command("subfinder", &schema, &opts, &["recon".into()]);
        assert!(cmd.contains("-t 50"), "got: {cmd}");
    }

    #[test]
    fn falsy_values_are_skipped() {
        let schema = schema_subfinder();
        let mut opts = RunOpts::new();
        opts.insert("threads".into(), "".into());
        opts.insert("rate_limit".into(), "false".into());
        let cmd = build_command("subfinder", &schema, &opts, &[]);
        assert_eq!(cmd.trim(), "subfinder");
    }

    #[test]
    fn build_input_single_flag() {
        let w = InputWiring { single: SingleMode::Flag("-d"), file: FileMode::Flag("-dL") };
        let cmd = build_input("subfinder", &["example.com".to_string()], &w, None);
        assert_eq!(cmd, "subfinder -d example.com");
    }

    #[test]
    fn build_input_picks_file_for_many_inputs() {
        let w = InputWiring { single: SingleMode::Flag("-d"), file: FileMode::Flag("-dL") };
        let cmd = build_input("subfinder", &["a".into(), "b".into()], &w, Some("/tmp/i.txt"));
        assert_eq!(cmd, "subfinder -dL /tmp/i.txt");
    }

    #[test]
    fn build_input_file_pipe() {
        let w = InputWiring { single: SingleMode::Pipe, file: FileMode::Pipe };
        let cmd = build_input("tool", &["a".into(), "b".into()], &w, Some("/tmp/in.txt"));
        assert_eq!(cmd, "cat /tmp/in.txt | tool");
    }

    #[test]
    fn shlex_quoting_protects_values() {
        let mut schema = OptSchema { opt_prefix: "-", ..OptSchema::default() };
        schema.meta_opts = vec![OptSpec::str("header")];
        let mut opts = RunOpts::new();
        opts.insert("header".into(), "X-A: hello world".into());
        let cmd = build_command("tool", &schema, &opts, &[]);
        assert!(cmd.contains("-header 'X-A: hello world'"), "got: {cmd}");
    }
}
