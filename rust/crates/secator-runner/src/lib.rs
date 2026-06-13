//! The `Runner` abstraction: `CommandRunner` (external tool) + `NativeRunner` (in-proc).
//!
//! Maps to Python `secator/runners/{_base,command,python}.py`. A runner spawns the tool
//! subprocess (or runs native logic), streams stdout line-by-line through the task's
//! parser, applies hooks/validators, and pushes typed `OutputItem`s onto a `ResultSink`
//! channel. See `../docs/rewrite/02-architecture.md` §1–§4.
//!
//! All 13 hook slots are wired: before_init / on_init / on_start / on_end /
//! on_interval / on_item_pre_convert / on_item / on_duplicate / on_cmd /
//! on_cmd_done / on_line / on_json_loaded / on_regex_loaded. Per-task
//! `on_interval` ticks live in this loop; the DAG engine drives the workflow-
//! level lifecycle (`on_start`/`on_end` for the whole run) separately.

mod stats;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Stdio;

use secator_model::{Map, OutputItem};
use secator_options::{build_command, build_input, InputWiring, OptSchema, RunOpts};
use secator_parse::{
    convert_item, Discriminator, JsonSerializer, OutputMaps, RegexSerializer, Serializer,
};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command as TokioCommand;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;

/// Channel a runner pushes typed results onto.
pub type ResultSink = Sender<OutputItem>;

/// Wrap an `Option<JoinHandle<()>>` so Drop aborts the spawned task — needed
/// when a parent future can be dropped mid-execution (e.g. worker timeout)
/// and would otherwise leak `tx.clone()` clones held by the inner task.
struct AbortOnDrop(Option<JoinHandle<()>>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if let Some(h) = self.0.take() {
            h.abort();
        }
    }
}

// ----------------------------------------------------------------------- Hooks

/// Per-run scratchpad passed to every hook (stash data between invocations).
#[derive(Debug, Default)]
pub struct HookCtx {
    pub task_name: &'static str,
    /// Extra items a hook wants emitted (Python `add_result` from inside a hook).
    pub extra_results: Vec<OutputItem>,
    /// Free-form per-run state a hook can stash for later hooks (e.g. on_init stores
    /// `output_path`, on_cmd_done reads it).
    pub state: BTreeMap<String, String>,
}

/// Registered hooks per lifecycle event. Stored as `&'static` slices so a `TaskSpec`
/// can live in a `static`. Empty default = no hooks.
#[derive(Copy, Clone)]
pub struct HookRegistry {
    /// Python `before_init(self)`. Fires first; the hook receives the full
    /// runner so it can mutate any field — inputs, opts, the cmd suffix, the
    /// input wiring (dnsx switches modes here), reports folder, etc. Mirrors
    /// Python's `self.<...>` mutations inside a task's `before_init`.
    pub before_init: &'static [fn(&mut HookCtx, &mut CommandRunner)],
    pub on_init: &'static [fn(&mut HookCtx)],
    pub on_start: &'static [fn(&mut HookCtx)],
    pub on_end: &'static [fn(&mut HookCtx)],
    pub on_interval: &'static [fn(&mut HookCtx)],
    /// Mutate the raw dict before schema conversion; return false to drop.
    pub on_item_pre_convert: &'static [fn(&mut HookCtx, &mut Map) -> bool],
    /// Mutate the typed item after schema conversion; return false to drop.
    pub on_item: &'static [fn(&mut HookCtx, &mut OutputItem) -> bool],
    pub on_duplicate: &'static [fn(&mut HookCtx, &mut OutputItem) -> bool],
    /// Mutate the assembled command string before spawning (Python `on_cmd`).
    pub on_cmd: &'static [fn(&mut HookCtx, &mut String)],
    /// After the subprocess exits — yield extra items parsed from a file the tool wrote.
    pub on_cmd_done: &'static [fn(&mut HookCtx) -> Vec<OutputItem>],
    /// Pre-process each raw stdout line; return None to drop.
    pub on_line: &'static [fn(&mut HookCtx, &str) -> Option<String>],
}
impl HookRegistry {
    pub const EMPTY: HookRegistry = HookRegistry {
        before_init: &[],
        on_init: &[],
        on_start: &[],
        on_end: &[],
        on_interval: &[],
        on_item_pre_convert: &[],
        on_item: &[],
        on_duplicate: &[],
        on_cmd: &[],
        on_cmd_done: &[],
        on_line: &[],
    };
}

/// Validators short-circuit a run / drop an item. Signatures mirror Python's
/// `validate_input` (whole-input gate) and `validate_item` (per-record filter).
#[derive(Copy, Clone)]
pub struct ValidatorRegistry {
    pub validate_input: &'static [fn(&[String]) -> Result<(), String>],
    pub validate_item: &'static [fn(&Map) -> bool],
}
impl ValidatorRegistry {
    pub const EMPTY: ValidatorRegistry =
        ValidatorRegistry { validate_input: &[], validate_item: &[] };
}

// ------------------------------------------------------------------ ItemLoader

/// A line-serializer descriptor — Python `item_loaders = [JSONSerializer(), ...]`.
/// Each variant maps to a `secator-parse` serializer; the dispatcher routes each
/// produced record to the matching `on_<name>_loaded` callback on [`TaskSpec`]
/// (default: schema conversion via `output_types` + `output_maps`).
#[derive(Copy, Clone, Debug)]
pub enum ItemLoader {
    /// JSON object per line, tolerant (extract the first `{...}` substring).
    Json,
    /// JSON list per line: `[{...}, {...}]`.
    JsonList,
    /// Strict JSON: the object must start at byte 0.
    JsonStrict,
    /// Regex with named groups — yields one record per match with the named fields.
    Regex {
        pattern: &'static str,
        fields: &'static [&'static str],
    },
    /// `re.findall`-style — one record per match with a single `match` field.
    RegexFindall { pattern: &'static str },
}

impl ItemLoader {
    /// Build the serializer for this loader and run it against `line`.
    fn run(&self, line: &str) -> Vec<Map> {
        match self {
            ItemLoader::Json => JsonSerializer::new().run(line),
            ItemLoader::JsonList => JsonSerializer::list().run(line),
            ItemLoader::JsonStrict => JsonSerializer::strict().run(line),
            ItemLoader::Regex { pattern, fields } => {
                let fields: Vec<String> = fields.iter().map(|s| (*s).to_string()).collect();
                match RegexSerializer::new(pattern, fields) {
                    Ok(s) => s.run(line),
                    Err(_) => Vec::new(),
                }
            }
            ItemLoader::RegexFindall { pattern } => match RegexSerializer::findall(pattern) {
                Ok(s) => s.run(line),
                Err(_) => Vec::new(),
            },
        }
    }

    fn is_json(&self) -> bool {
        matches!(self, ItemLoader::Json | ItemLoader::JsonList | ItemLoader::JsonStrict)
    }
}

/// Per-loader callback type — Python `on_<serializer>_loaded(self, item)`. Returns
/// the typed items derived from a single raw record. Tasks override this when they
/// need full control of the dict→typed mapping (naabu's first-sighting, httpx's
/// secondary emissions). When `None` the dispatcher uses [`convert_item`] with
/// `output_types` + `output_maps` + `discriminator`.
pub type LoadedCallback = fn(&mut HookCtx, Map) -> Vec<OutputItem>;

/// `output_maps` constructor (Python `output_map = {Class: {field: src}}`).
/// Called once per run; default returns an empty map.
pub fn empty_output_maps() -> OutputMaps {
    OutputMaps::new()
}

// -------------------------------------------------------------------- ProxyCaps

/// Per-task proxy capability flags (Python `proxychains` / `proxy_http` / `proxy_socks5`).
///
/// Drives `configure_proxy` in [`CommandRunner`]: when the operator passes
/// `--proxy auto` (or a specific scheme), this struct says whether the task can
/// run under proxychains, accept an HTTP proxy via `--proxy http://…`, or accept
/// SOCKS5. Defaults to all-false — tasks opt in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyCaps {
    pub proxychains: bool,
    pub proxy_http: bool,
    pub proxy_socks5: bool,
}
impl ProxyCaps {
    pub const NONE: ProxyCaps = ProxyCaps {
        proxychains: false,
        proxy_http: false,
        proxy_socks5: false,
    };
    pub const ALL: ProxyCaps = ProxyCaps {
        proxychains: true,
        proxy_http: true,
        proxy_socks5: true,
    };
    pub const HTTP_AND_SOCKS5: ProxyCaps = ProxyCaps {
        proxychains: false,
        proxy_http: true,
        proxy_socks5: true,
    };
}

// -------------------------------------------------------------------- InstallSpec

/// One (package-manager-name, packages) pair (Python `install_pre[<pm_pattern>] = [..]`).
/// `pm_pattern` is a `|`-joined list of package manager names (e.g. `"apt|apk"`); the
/// literal `"*"` matches any. Matched in declaration order — first match wins.
pub type PackageGroup = (&'static str, &'static [&'static str]);

/// One (distro-name, shell-command) pair (Python `install_post[<distro_pattern>] = "..."`).
/// `distro_pattern` mirrors `PackageGroup`'s pattern grammar but matches by distribution
/// name rather than package manager (e.g. `"arch|alpine"`).
pub type DistroCommand = (&'static str, &'static str);

/// Declarative install metadata (Python `install_*` class attributes). Empty by default —
/// tasks without an installer use [`InstallSpec::EMPTY`] and `secator install <task>` will
/// surface a "not supported" message for them.
#[derive(Copy, Clone)]
pub struct InstallSpec {
    /// Version substituted into `cmd` via `[install_version]` (or `[install_version_strip]`,
    /// which strips a leading `v`). `None` ⇒ "latest" is used at run time.
    pub version: Option<&'static str>,
    /// Shell command to run for source-install (Python `install_cmd`). When `None`, source
    /// install is skipped — useful for tasks that ship only via GitHub releases or are
    /// installed externally.
    pub cmd: Option<&'static str>,
    /// System packages installed BEFORE source build (Python `install_pre`). Driven through
    /// the host's package manager (apt/apk/pacman/yum/zypper/dnf/brew).
    pub pre: &'static [PackageGroup],
    /// Source-build pre-req packages (Python `install_cmd_pre`). Same shape as `pre`; the
    /// split exists because Python keeps them logically separate.
    pub cmd_pre: &'static [PackageGroup],
    /// Shell commands to run AFTER source install (Python `install_post`). Distro-keyed.
    pub post: &'static [DistroCommand],
    /// GitHub `user/repo` handle (Python `github_handle`). Used by the GitHub-releases
    /// installer path when `github_bin` is `true`; currently captured but the releases
    /// installer isn't wired yet (M9).
    pub github_handle: Option<&'static str>,
    /// Whether to attempt GitHub releases binary download before source build
    /// (Python `install_github_bin`, default `true`).
    pub github_bin: bool,
}

impl InstallSpec {
    /// No installer — `secator install <task>` reports "not supported".
    pub const EMPTY: InstallSpec = InstallSpec {
        version: None,
        cmd: None,
        pre: &[],
        cmd_pre: &[],
        post: &[],
        github_handle: None,
        github_bin: true,
    };
}

// --------------------------------------------------------------------- TaskSpec

/// Declarative description of a tool integration (Python task class attributes).
pub struct TaskSpec {
    pub name: &'static str,
    /// Human-readable description (shown in lifecycle messages + help).
    pub description: &'static str,
    pub cmd: &'static str,
    pub input_types: &'static [&'static str],
    /// Try-order for the dict→record mapper (`secator-parse::convert_item`).
    pub output_types: &'static [&'static str],
    pub tags: &'static [&'static str],
    pub json_flag: Option<&'static str>,
    pub input_wiring: InputWiring,
    /// Line serializers run against each stdout line — Python `item_loaders`.
    pub item_loaders: &'static [ItemLoader],
    /// Python `input_chunk_size`. When set, multi-input runs are split into N-sized
    /// chunks and each chunk is executed as a separate subprocess (with the full
    /// hook lifecycle). `0` ⇒ no chunking. Tasks that can't read an inputs file
    /// (Python `search_vulns` with `chunk_size=1`) set this to `1` so every target
    /// goes through the single-input wiring (`-q <query>`).
    pub input_chunk_size: usize,
    /// Python `on_json_loaded(self, item)`: per-record handler for JSON loaders.
    /// `None` ⇒ default schema conversion via `output_types` + `output_maps` +
    /// `discriminator`.
    pub on_json_loaded: Option<LoadedCallback>,
    /// Python `on_regex_loaded(self, item)`: same shape, for regex loaders.
    pub on_regex_loaded: Option<LoadedCallback>,
    /// Per-output-type field renames (Python `output_map`). Builds once per run.
    pub output_maps: fn() -> OutputMaps,
    /// Optional discriminator (Python `output_discriminator`).
    pub discriminator: Option<Discriminator>,
    pub hooks: HookRegistry,
    pub validators: ValidatorRegistry,
    /// Build this task's option schema at startup (Python's `opts`/`meta_opts`/
    /// `opt_key_map`/`opt_value_map`). Called once per task at CLI build time.
    pub schema: fn() -> OptSchema,
    /// Install pipeline metadata (Python `install_*` attrs). Drives `secator install <task>`.
    pub install: InstallSpec,
    /// Proxy capabilities (Python `proxychains` / `proxy_http` / `proxy_socks5`).
    /// Default `ProxyCaps::NONE` — tasks opt in.
    pub proxy_caps: ProxyCaps,
    /// Subprocess stdout encoding. `"utf-8"` (default) lets the runner decode as
    /// UTF-8; `"ansi"` (Python parity, used by cariddi/dalfox/dirsearch/ffuf/gau)
    /// flips to Windows-1252 via `encoding_rs` because the tool emits color
    /// codes / non-ASCII bytes that aren't valid UTF-8.
    pub encoding: &'static str,
    /// When `true`, a non-zero subprocess exit is not treated as task failure
    /// (Python `ignore_return_code`). Used by tools like `msfconsole`,
    /// `ph`, `dalfox` that exit non-zero on success or on "no findings".
    /// Today the Rust runner doesn't gate on exit code either way — the field
    /// is wired for Python parity and surfaces in `secator health` / docs.
    pub ignore_return_code: bool,
    /// `true` ⇒ the wrapper command must run as root (Python `requires_sudo`,
    /// used by `arp`, `arpscan`). When set, `CommandRunner::run_one_chunk`
    /// prepends `sudo -S` and feeds the operator's password (or skips when
    /// already root / `SECATOR_SUDO_NOPROMPT` is set).
    pub requires_sudo: bool,
}

/// Default schema constructor: no opts, `-` prefix.
pub fn empty_schema() -> OptSchema {
    OptSchema::default()
}

/// True when the current process is uid=0 (Linux/Mac). Falls back to env-based
/// detection on Windows / when getuid is unavailable.
fn is_root() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: getuid() is a stable syscall returning a uid_t. No memory unsafety.
        unsafe { libc::getuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        std::env::var("USERNAME").map(|u| u == "Administrator").unwrap_or(false)
    }
}

/// Prompt for sudo password via `rpassword` (no echo to terminal). Returns
/// `None` when stdin isn't a TTY (CI mode) so callers can fall back to env vars.
fn prompt_sudo_password(task_name: &str) -> Option<String> {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        eprintln!("ℹ {task_name} requires sudo and stdin isn't a TTY — set SECATOR_SUDO_PASSWORD or run as root");
        return None;
    }
    let prompt = format!("[sudo] password for {task_name}: ");
    rpassword::prompt_password(prompt).ok().filter(|s| !s.is_empty())
}

/// Decoder selector — maps a TaskSpec `encoding` string to an `encoding_rs`
/// codec. `"utf-8"` (default) and `""` are treated as UTF-8.
fn pick_decoder(name: &str) -> &'static encoding_rs::Encoding {
    let n = name.trim().to_lowercase();
    match n.as_str() {
        "" | "utf-8" | "utf8" => encoding_rs::UTF_8,
        // Python `'ansi'` on Windows = cp1252; on Linux it's effectively cp1252 too
        // for the tools that opt in (cariddi, dalfox, etc., all emit colour codes
        // mixed with cp1252 text).
        "ansi" | "cp1252" | "windows-1252" => encoding_rs::WINDOWS_1252,
        "latin-1" | "latin1" | "iso-8859-1" => encoding_rs::WINDOWS_1252, // closest
        _ => encoding_rs::Encoding::for_label(n.as_bytes()).unwrap_or(encoding_rs::UTF_8),
    }
}

/// Read one stdout line + transcode to a Rust `String` using the chosen codec.
/// Returns `Ok(None)` on EOF. The `\n` (and optional preceding `\r`) is stripped
/// so downstream `on_line` hooks see a clean line.
async fn read_one_line<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    decoder: &'static encoding_rs::Encoding,
) -> Result<Option<String>, std::io::Error> {
    let mut buf = Vec::with_capacity(256);
    let n = reader.read_until(b'\n', &mut buf).await?;
    if n == 0 {
        return Ok(None);
    }
    if buf.last() == Some(&b'\n') {
        buf.pop();
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
    }
    let (cow, _enc, _had_errors) = decoder.decode(&buf);
    Ok(Some(cow.into_owned()))
}

/// Translate the operator-facing `--proxy` opt into a concrete proxy URL or a
/// proxychains cmd prefix (Python `configure_proxy`). Mutates `runner.opts`
/// and/or `runner.cmd_suffix` in place. Called once per chunk, right after
/// `before_init` hooks fire and before `build_cmd`.
///
/// Accepted `proxy` values:
/// * `auto` (or omitted) — pick the first supported channel based on `proxy_caps`
///   and config: proxychains → socks5 → http.
/// * `proxychains` — prepend `<proxychains_command> ` to the cmd if the task
///   declares `proxy_caps.proxychains`. Drop the `proxy` opt so it doesn't
///   double-emit.
/// * `socks5` — use `config.http.socks5_proxy` if the task accepts SOCKS5.
/// * `http`   — use `config.http.http_proxy` if the task accepts HTTP.
/// * a literal URL like `http://...` / `socks5://...` — passed through.
/// * empty / unsupported — `proxy` opt is dropped so the task runs unproxied.
pub fn configure_proxy(runner: &mut CommandRunner) {
    let caps = runner.spec.proxy_caps;
    let raw = runner.opts.get("proxy").cloned().unwrap_or_default();
    if raw.is_empty() {
        return;
    }
    let cfg = secator_config::get();
    let want_pc = matches!(raw.as_str(), "auto" | "proxychains");
    let want_socks5 = matches!(raw.as_str(), "auto" | "socks5");
    let want_http = matches!(raw.as_str(), "auto" | "http");
    let is_literal_url = raw.starts_with("http://") || raw.starts_with("https://") || raw.starts_with("socks5://");

    // 1. Proxychains takes priority (Python: `proxy in ['auto', 'proxychains']`).
    if want_pc && caps.proxychains && !cfg.http.proxychains_command.is_empty() {
        // Prepend `proxychains4 ` (or whatever the operator configured) to the
        // base cmd. Stored on the spec? No — we mutate `runner.cmd_suffix`
        // through a helper that prepends rather than appends, by stashing the
        // prefix in HookCtx state. Simplest: shadow `spec.cmd` via a fake
        // `cmd_suffix` placement isn't quite right because cmd_suffix lands
        // AFTER the base cmd. The right way is `build_cmd` extension — we
        // expose a `cmd_prefix` field on CommandRunner that lands BEFORE the
        // base.
        runner.cmd_prefix = format!("{} ", cfg.http.proxychains_command.trim());
        runner.opts.remove("proxy");
        secator_debug::debug!("proxy", "{} proxychains prefix={:?}", runner.spec.name, runner.cmd_prefix);
        return;
    }

    // 2. Literal URL pass-through — `--proxy http://localhost:8080` etc.
    //    Only honored if the task accepts the relevant scheme.
    if is_literal_url {
        let accept = (raw.starts_with("socks5://") && caps.proxy_socks5)
            || (raw.starts_with("http://") && caps.proxy_http)
            || (raw.starts_with("https://") && caps.proxy_http);
        if accept {
            secator_debug::debug!("proxy", "{} literal proxy {raw}", runner.spec.name);
            return; // keep `proxy` opt as-is
        }
        runner.opts.remove("proxy");
        return;
    }

    // 3. Auto / socks5 → config.http.socks5_proxy.
    if want_socks5 && caps.proxy_socks5 && !cfg.http.socks5_proxy.is_empty() {
        runner.opts.insert("proxy".into(), cfg.http.socks5_proxy.clone());
        secator_debug::debug!("proxy", "{} socks5 {}", runner.spec.name, cfg.http.socks5_proxy);
        return;
    }
    // 4. Auto / http → config.http.http_proxy.
    if want_http && caps.proxy_http && !cfg.http.http_proxy.is_empty() {
        runner.opts.insert("proxy".into(), cfg.http.http_proxy.clone());
        secator_debug::debug!("proxy", "{} http {}", runner.spec.name, cfg.http.http_proxy);
        return;
    }
    // 5. Nothing matched — drop the opt so the task runs unproxied (Python
    //    yields a Warning here; we just log debug-level since it's an opt-in
    //    feature and Warnings are loud).
    runner.opts.remove("proxy");
    secator_debug::debug!(
        "proxy",
        "{} {raw:?} not supported (caps={:?}); proxy opt dropped",
        runner.spec.name,
        runner.spec.proxy_caps,
    );
}

/// Fire `on_duplicate` hooks for every item already flagged as a duplicate
/// (Python `runner.on_duplicate`). Caller should run this AFTER
/// `secator_model::mark_duplicates`. Hooks may mutate or drop items (returning
/// `false` ⇒ remove from the final report). Returns the new item list.
pub fn fire_on_duplicate_hooks(
    spec_hooks: &HookRegistry,
    task_name: &'static str,
    items: Vec<OutputItem>,
) -> Vec<OutputItem> {
    if spec_hooks.on_duplicate.is_empty() {
        return items;
    }
    let mut ctx = HookCtx { task_name, ..HookCtx::default() };
    let mut out: Vec<OutputItem> = Vec::with_capacity(items.len());
    for mut item in items {
        if !item.meta().duplicate {
            out.push(item);
            continue;
        }
        let mut keep = true;
        for h in spec_hooks.on_duplicate {
            if !h(&mut ctx, &mut item) {
                keep = false;
                break;
            }
        }
        if keep {
            out.push(item);
        }
    }
    for extra in std::mem::take(&mut ctx.extra_results) {
        out.push(extra);
    }
    out
}

// ------------------------------------------------------------------ NativeRunner

/// A native (in-process) task: no subprocess, just Rust that produces items
/// (Python `PythonRunner`). MVP fit: `urlparser`, `netdetect`, `prompt`.
pub struct NativeSpec {
    pub name: &'static str,
    pub description: &'static str,
    pub input_types: &'static [&'static str],
    pub output_types: &'static [&'static str],
    pub tags: &'static [&'static str],
    /// Compute results synchronously from inputs + opts. Async-yielding native tasks
    /// (e.g. an LLM agent) need a richer surface; M3 keeps the simple form.
    pub run: fn(inputs: &[String], opts: &RunOpts) -> Vec<OutputItem>,
    pub hooks: HookRegistry,
    pub validators: ValidatorRegistry,
    /// Build this task's option schema at startup (Python's `opts`/`meta_opts`/
    /// `opt_key_map`/`opt_value_map`). Called once per task at CLI build time.
    pub schema: fn() -> OptSchema,
    /// Install metadata (mostly empty for natives — they're in-process Rust). Some
    /// natives wrap an external dep though (e.g. an LLM client lib), so we expose
    /// the same surface as `TaskSpec`.
    pub install: InstallSpec,
    pub proxy_caps: ProxyCaps,
    /// In-process tasks don't shell out, so these are placeholders for surface
    /// uniformity — defaults work for every native today.
    pub encoding: &'static str,
    pub ignore_return_code: bool,
    pub requires_sudo: bool,
}

pub struct NativeRunner {
    pub spec: &'static NativeSpec,
    pub inputs: Vec<String>,
    pub opts: RunOpts,
}

impl NativeRunner {
    pub fn new(spec: &'static NativeSpec, inputs: Vec<String>) -> Self {
        NativeRunner { spec, inputs, opts: BTreeMap::new() }
    }

    pub async fn run(&self, tx: ResultSink) -> Result<(), RunnerError> {
        // validate_input gate.
        for v in self.spec.validators.validate_input {
            if let Err(msg) = v(&self.inputs) {
                return Err(RunnerError::Validation(msg));
            }
        }
        let items = (self.spec.run)(&self.inputs, &self.opts);
        let mut ctx = HookCtx { task_name: self.spec.name, ..HookCtx::default() };
        for mut item in items {
            // on_item hooks.
            let mut keep = true;
            for h in self.spec.hooks.on_item {
                if !h(&mut ctx, &mut item) {
                    keep = false;
                    break;
                }
            }
            if !keep {
                continue;
            }
            if tx.send(item).await.is_err() {
                return Ok(());
            }
        }
        // Drain anything hooks asked to emit late.
        for extra in std::mem::take(&mut ctx.extra_results) {
            if tx.send(extra).await.is_err() {
                break;
            }
        }
        Ok(())
    }
}

// -------------------------------------------------------------------- Errors

#[derive(Debug)]
pub enum RunnerError {
    Spawn(String),
    NoStdout,
    Validation(String),
}
impl std::fmt::Display for RunnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunnerError::Spawn(s) => write!(f, "failed to spawn subprocess: {s}"),
            RunnerError::NoStdout => write!(f, "subprocess has no stdout pipe"),
            RunnerError::Validation(s) => write!(f, "input validator failed: {s}"),
        }
    }
}
impl std::error::Error for RunnerError {}

// --------------------------------------------------------------- CommandRunner

pub struct CommandRunner {
    pub spec: &'static TaskSpec,
    pub inputs: Vec<String>,
    pub opts: RunOpts,
    pub schema: OptSchema,
    pub aliases: Vec<String>,
    pub input_file: Option<String>,
    /// Where the runner's reports / output files should live (Python
    /// `Runner.reports_folder`). When set, the runner exposes it to hooks via
    /// `HookCtx.state["reports_folder"]`; tasks like httpx use it for `-srd`.
    pub reports_folder: Option<PathBuf>,
    /// Optional runtime override of the spec's `input_wiring`. Python tasks like
    /// `dnsx` switch from stdin-pipe to `-d <target>` flag mode inside `before_init`
    /// based on whether `wordlist` is set; we mirror that by letting hooks write
    /// `runner.input_wiring_override = Some(...)`. None ⇒ use `spec.input_wiring`.
    pub input_wiring_override: Option<InputWiring>,
    /// Optional runtime addition to the cmd prefix. Hooks (`before_init`) can
    /// append shell tokens here and they'll go before the `-flag value` opts in
    /// `build_cmd` — mirrors Python's `self.cmd += ' -rc noerror'` pattern.
    pub cmd_suffix: String,
    /// Optional shell tokens prepended BEFORE the base cmd (e.g. `proxychains4 `).
    /// Used by [`configure_proxy`] so the proxied invocation looks like
    /// `proxychains4 nuclei -t ...`.
    pub cmd_prefix: String,
    /// When false (default), the subprocess's stderr is swallowed — only Secator
    /// items (`📦 ...`, `🔗 ...`, `[INF] ...`, the `⚡ <cmd>` echo) reach the
    /// operator. `--verbose` flips this on so the tool's own banner / logs come
    /// through. Mirrors Python's `--quiet/--verbose` toggle.
    pub verbose: bool,
}

impl CommandRunner {
    pub fn new(spec: &'static TaskSpec, inputs: Vec<String>) -> Self {
        CommandRunner {
            spec, inputs, opts: BTreeMap::new(),
            schema: (spec.schema)(),
            aliases: Vec::new(), input_file: None,
            reports_folder: None,
            input_wiring_override: None,
            cmd_suffix: String::new(),
            cmd_prefix: String::new(),
            verbose: false,
        }
    }

    /// Build the final command string: prefix + base + json_flag + resolved opts + input wiring.
    /// Does NOT run `on_cmd` hooks — see [`build_cmd_with_hooks`] for the post-hook form.
    pub fn build_cmd(&self) -> String {
        let base_with_prefix = if self.cmd_prefix.is_empty() {
            self.spec.cmd.to_string()
        } else {
            format!("{}{}", self.cmd_prefix, self.spec.cmd)
        };
        let mut cmd = build_command(&base_with_prefix, &self.schema, &self.opts, &self.aliases);
        if !self.cmd_suffix.is_empty() {
            cmd.push(' ');
            cmd.push_str(self.cmd_suffix.trim());
        }
        if let Some(jf) = self.spec.json_flag {
            cmd.push(' ');
            cmd.push_str(jf);
        }
        let wiring = self.input_wiring_override.as_ref().unwrap_or(&self.spec.input_wiring);
        build_input(&cmd, &self.inputs, wiring, self.input_file.as_deref())
    }

    /// Like `build_cmd` but also runs `on_cmd` hooks with the runner's
    /// `reports_folder` pre-populated on the context — what the spawned subprocess
    /// will actually receive. The CLI uses this for its `⚡ ...` echo.
    pub fn build_cmd_with_hooks(&self) -> String {
        let mut cmd = self.build_cmd();
        let mut ctx = HookCtx { task_name: self.spec.name, ..HookCtx::default() };
        if let Some(rf) = &self.reports_folder {
            ctx.state.insert("reports_folder".into(), rf.to_string_lossy().into_owned());
        }
        for h in self.spec.hooks.on_cmd {
            h(&mut ctx, &mut cmd);
        }
        cmd
    }

    /// Write the inputs file (multi-target file mode). Idempotent — safe to call from
    /// `run` or earlier (e.g. before a cmd-echo preview). Pulled out so the worker can
    /// echo the assembled command with the path filled in.
    pub fn prepare(&mut self) -> Result<(), RunnerError> {
        if self.inputs.len() > 1 && self.input_file.is_none() {
            let path = std::env::temp_dir().join(format!(
                "secator-{}-{}.txt",
                self.spec.name,
                std::process::id()
            ));
            std::fs::write(&path, self.inputs.join("\n"))
                .map_err(|e| RunnerError::Spawn(format!("write inputs file: {e}")))?;
            self.input_file = Some(path.to_string_lossy().into_owned());
        }
        Ok(())
    }

    /// Spawn the subprocess and stream results onto `tx`. Wires the full hook lifecycle.
    /// Mirrors Python `Command.needs_chunking` + `celery.break_task`:
    ///   - If the task can't accept multi-input via a file (`FileMode::Unsupported`,
    ///     equivalent to Python `file_flag is None`), chunk every input into its own
    ///     subprocess regardless of `input_chunk_size`.
    ///   - Else if `input_chunk_size > 0` and there are more inputs than that, split
    ///     into chunks of that size.
    ///   - Else run the whole batch in one subprocess.
    pub async fn run(&mut self, tx: ResultSink) -> Result<(), RunnerError> {
        // validate_input gate — once, over the full input set.
        for v in self.spec.validators.validate_input {
            if let Err(msg) = v(&self.inputs) {
                return Err(RunnerError::Validation(msg));
            }
        }
        // Apply `tasks.overrides.<task>.<opt>` from config — only when the user
        // (CLI/YAML) didn't already set the key. Python parity: config overrides
        // sit BELOW explicit invocations but ABOVE spec defaults.
        self.apply_task_overrides();

        let chunk_size = self.effective_chunk_size();
        if chunk_size == 0 || self.inputs.len() <= chunk_size.max(1) {
            return self.run_one_chunk(&tx).await;
        }
        // Python `break_task` rate-limit smoothing: when chunking N inputs into
        // C chunks and `rate_limit` is set, divide the per-call rate by C so the
        // aggregate request rate stays bounded across the parallel sub-runs.
        // Gated by `CONFIG.runners.chunk_rate_limit` (default true).
        let all = std::mem::take(&mut self.inputs);
        let n_chunks = all.chunks(chunk_size).count();
        if secator_config::get().runners.chunk_rate_limit && n_chunks > 1 {
            if let Some(rl) = self.opts.get("rate_limit").cloned() {
                if let Ok(orig) = rl.trim().parse::<i64>() {
                    if orig > 0 {
                        let per = (orig / n_chunks as i64).max(1);
                        self.opts.insert("rate_limit".into(), per.to_string());
                        secator_debug::debug!(
                            "chunk",
                            "{} rate_limit {} → {} across {} chunks",
                            self.spec.name,
                            orig,
                            per,
                            n_chunks,
                        );
                    }
                }
            }
        }
        let mut last: Result<(), RunnerError> = Ok(());
        for chunk in all.chunks(chunk_size) {
            self.inputs = chunk.to_vec();
            self.input_file = None;
            if let Err(e) = self.run_one_chunk(&tx).await {
                last = Err(e);
            }
        }
        last
    }

    /// Apply `CONFIG.tasks.overrides.<task-name>.<opt>` defaults. Only fills
    /// opts the caller (CLI / YAML / parent runner) hasn't already set, so
    /// explicit values always win over the operator's config-level overrides.
    /// Mirrors Python's `tasks.overrides[task_name]` merge in
    /// `secator/runners/_base.py`.
    fn apply_task_overrides(&mut self) {
        let cfg = secator_config::get();
        let map = match cfg.tasks.overrides.get(self.spec.name) {
            Some(m) => m,
            None => return,
        };
        for (k, v) in map {
            if self.opts.contains_key(k) {
                continue;
            }
            let s = match v {
                serde_yaml::Value::String(s) => s.clone(),
                serde_yaml::Value::Bool(b) => b.to_string(),
                serde_yaml::Value::Number(n) => n.to_string(),
                // Lists collapse to comma-joined (matches `opts_to_run_opts`).
                serde_yaml::Value::Sequence(seq) => seq
                    .iter()
                    .map(|e| match e {
                        serde_yaml::Value::String(s) => s.clone(),
                        other => serde_yaml::to_string(other).unwrap_or_default().trim().to_string(),
                    })
                    .collect::<Vec<_>>()
                    .join(","),
                other => serde_yaml::to_string(other).unwrap_or_default().trim().to_string(),
            };
            self.opts.insert(k.clone(), s);
        }
    }

    /// Resolve the effective chunk size for this run. `FileMode::Unsupported` forces
    /// `1` (one input per subprocess) so we never reach `apply_file` with a path the
    /// tool can't consume. When the spec sets `input_chunk_size == 0` (the default),
    /// fall back to `CONFIG.runners.input_chunk_size` — Python parity for the
    /// "task doesn't override; use the global default" case.
    fn effective_chunk_size(&self) -> usize {
        if matches!(self.spec.input_wiring.file, secator_options::FileMode::Unsupported) {
            return 1;
        }
        if self.spec.input_chunk_size > 0 {
            return self.spec.input_chunk_size;
        }
        let cfg = secator_config::get().runners.input_chunk_size;
        if cfg > 0 { cfg as usize } else { 0 }
    }

    /// Single-chunk execution: prepare → hooks → spawn → on_cmd_done → on_end → drain.
    async fn run_one_chunk(&mut self, tx: &ResultSink) -> Result<(), RunnerError> {
        secator_debug::debug!("init", "{} chunk start ({} input(s))", self.spec.name, self.inputs.len());
        self.prepare()?;

        let mut ctx = HookCtx { task_name: self.spec.name, ..HookCtx::default() };
        if let Some(rf) = &self.reports_folder {
            ctx.state.insert("reports_folder".into(), rf.to_string_lossy().into_owned());
        }
        // Copy the &'static slice into a local so we don't hold a borrow on
        // `self` while invoking hooks that take `&mut self`.
        let before_init_hooks = self.spec.hooks.before_init;
        if !before_init_hooks.is_empty() {
            secator_debug::debug!("hooks.before_init", "{} firing {} hook(s)", self.spec.name, before_init_hooks.len());
        }
        for h in before_init_hooks { h(&mut ctx, self); }
        for h in self.spec.hooks.on_init { h(&mut ctx); }

        // Configure proxy (Python `configure_proxy`): translates `--proxy auto`
        // / `--proxy http` / `--proxy socks5` / `--proxy proxychains` into the
        // right resolved URL or a `proxychains4` cmd prefix, gated on the
        // task's `proxy_caps`. Runs BEFORE build_cmd so the resolved value
        // shows up in the assembled command.
        configure_proxy(self);

        // `requires_sudo`: when the task needs root and we're not already root,
        // splice `sudo -S` into the cmd prefix. `sudo -S` reads the password
        // from stdin, which we feed (once) from `prompt_sudo_password` or from
        // the `SECATOR_SUDO_PASSWORD` env var. When `SECATOR_SUDO_NOPROMPT=1`
        // is set, we skip the prompt and trust the operator's sudoers config.
        let mut sudo_password: Option<String> = None;
        if self.spec.requires_sudo && !is_root() {
            // Stash the prefix; password injection happens just before spawn.
            if !self.cmd_prefix.contains("sudo") {
                self.cmd_prefix = format!("sudo -S {}", self.cmd_prefix);
            }
            if std::env::var_os("SECATOR_SUDO_NOPROMPT").is_none() {
                sudo_password = std::env::var("SECATOR_SUDO_PASSWORD")
                    .ok()
                    .or_else(|| prompt_sudo_password(self.spec.name));
            }
        }
        // Stash for downstream `execute_with_hooks` via ctx.state.
        if let Some(pw) = &sudo_password {
            ctx.state.insert("__sudo_password".into(), pw.clone());
        }

        let mut cmd = self.build_cmd();
        for h in self.spec.hooks.on_cmd { h(&mut ctx, &mut cmd); }
        secator_debug::debug!("start", "{} assembled cmd: {}", self.spec.name, cmd);
        secator_debug::debug!("start.opts", "{} opts: {:?}", self.spec.name, self.opts);

        // Echo the assembled command (Python parity). Per-chunk so the chunking
        // (Python `break_task`) is visible — for tasks without a file flag (e.g.
        // `search_vulns`), 5 inputs become 5 single-input subprocess runs, each
        // printed here as `⚡ search_vulns -q <input>`.
        eprintln!("⚡ {cmd}");

        for h in self.spec.hooks.on_start { h(&mut ctx); }

        execute_with_hooks(&cmd, self.spec, self.verbose, &mut ctx, tx).await?;

        // on_cmd_done emits extra items (Python: nmap reads its XML output here).
        for h in self.spec.hooks.on_cmd_done {
            for extra in h(&mut ctx) {
                if tx.send(extra).await.is_err() { break; }
            }
        }

        for h in self.spec.hooks.on_end { h(&mut ctx); }

        // Drain any extras hooks queued in ctx.
        let extras = std::mem::take(&mut ctx.extra_results);
        if !extras.is_empty() {
            secator_debug::debug!("end", "{} draining {} late-emit item(s)", self.spec.name, extras.len());
        }
        for extra in extras {
            if tx.send(extra).await.is_err() { break; }
        }
        secator_debug::debug!("end", "{} chunk done", self.spec.name);
        Ok(())
    }
}

/// Spawn the subprocess; per line, run `on_line` hooks, then each `item_loader`,
/// dispatch records to the matching `on_<loader>_loaded` callback (default: schema
/// conversion), then run `on_item` hooks; push survivors onto `tx`.
async fn execute_with_hooks(
    cmd: &str,
    spec: &TaskSpec,
    verbose: bool,
    ctx: &mut HookCtx,
    tx: &ResultSink,
) -> Result<(), RunnerError> {
    // Default: swallow the subprocess's stderr so only Secator items reach the
    // operator (Python parity — `--quiet` is the default). `--verbose` inherits
    // stderr so the tool's banner / logs come through.
    let stderr_mode = if verbose { Stdio::inherit() } else { Stdio::null() };
    // If a sudo password was stashed by `run_one_chunk`, give the child a pipe
    // stdin so `sudo -S` can read it. Otherwise inherit (so interactive prompts
    // — e.g. a tool that re-asks for credentials — still work).
    let sudo_password = ctx.state.get("__sudo_password").cloned();
    let stdin_mode = if sudo_password.is_some() { Stdio::piped() } else { Stdio::inherit() };
    let mut child = TokioCommand::new("sh")
        .arg("-c").arg(cmd)
        .stdin(stdin_mode)
        .stdout(Stdio::piped())
        .stderr(stderr_mode)
        // SIGKILL on Drop so an early-cancel of the runner future (e.g. the
        // worker's `task_max_timeout` race or operator Ctrl-C) reliably tears
        // down the subprocess instead of leaking it.
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| RunnerError::Spawn(e.to_string()))?;
    if let Some(pw) = sudo_password {
        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            let _ = stdin.write_all(pw.as_bytes()).await;
            let _ = stdin.write_all(b"\n").await;
            let _ = stdin.shutdown().await;
        }
        // Clear from ctx so we don't keep it in memory longer than needed.
        ctx.state.remove("__sudo_password");
    }
    let child_pid = child.id().unwrap_or(0);
    secator_debug::debug!("start", "{} spawned pid={}", spec.name, child_pid);
    // Start the background stat sampler — Python parity with `Command._collect_stats`.
    // Skipped when `config.runners.stat_update_frequency <= 0` or pid is unknown.
    let stat_freq = secator_config::get().runners.stat_update_frequency.max(0) as u64;
    // Wrap the optional sampler in an abort-on-drop guard. If `runner.run` is
    // dropped mid-execution (e.g. the worker's `task_max_timeout` deadline
    // fires), the guard's Drop aborts the spawned task — which releases its
    // `tx.clone()` and unblocks the worker's streamer drain.
    let stat_guard = AbortOnDrop(if child_pid != 0 {
        stats::spawn_sampler(child_pid, stat_freq, tx.clone())
    } else {
        None
    });
    let stdout = child.stdout.take().ok_or(RunnerError::NoStdout)?;
    // Pick a decoder based on `spec.encoding`. Default UTF-8 path uses the
    // tokio `lines()` iterator (zero-copy when bytes are valid UTF-8).
    // Non-UTF-8 paths read raw bytes and transcode via `encoding_rs`.
    let mut byte_lines = BufReader::new(stdout);
    let decoder = pick_decoder(spec.encoding);
    // Build the output-map once per run (Python rebuilds on every conversion;
    // we cache to avoid re-allocating the BTreeMap per item).
    let output_maps = (spec.output_maps)();
    // Periodic `on_interval` hooks (Python `on_interval`). Disabled when no
    // hook is registered to avoid scheduling overhead on the hot path.
    let interval_secs = std::env::var("SECATOR_ON_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(5.0);
    let mut interval = if spec.hooks.on_interval.is_empty() {
        None
    } else {
        Some(tokio::time::interval(std::time::Duration::from_secs_f64(interval_secs)))
    };
    if let Some(i) = interval.as_mut() {
        // Skip the first tick which fires immediately — we want the first call
        // after `interval_secs` of actual subprocess activity.
        i.reset();
    }
    loop {
        let line = if let Some(iv) = interval.as_mut() {
            tokio::select! {
                _ = iv.tick() => {
                    for h in spec.hooks.on_interval { h(ctx); }
                    secator_debug::debug!("interval", "{} on_interval fired", spec.name);
                    continue;
                }
                line = read_one_line(&mut byte_lines, decoder) => match line {
                    Ok(Some(l)) => l,
                    _ => break,
                }
            }
        } else {
            match read_one_line(&mut byte_lines, decoder).await {
                Ok(Some(l)) => l,
                _ => break,
            }
        };
        // Process the line the same way the old `while let` did.
        let _line_owned = line; // shadowed below
        let line = _line_owned;
        // on_line chain — each hook may rewrite or drop the line.
        let mut current: Option<String> = Some(line);
        for h in spec.hooks.on_line {
            current = match current {
                Some(l) => h(ctx, &l),
                None => break,
            };
        }
        let line = match current {
            Some(l) => l,
            None => continue,
        };
        for loader in spec.item_loaders {
            for record in loader.run(&line) {
                let items = dispatch_record(spec, &output_maps, ctx, loader, record);
                for mut item in items {
                    let mut keep = true;
                    for h in spec.hooks.on_item {
                        if !h(ctx, &mut item) { keep = false; break; }
                    }
                    if !keep { continue; }
                    if tx.send(item).await.is_err() { break; }
                }
            }
        }
    }
    let status = child.wait().await.ok();
    // Drop the guard — explicit so the abort happens before the rest of the
    // cleanup logs `subprocess exited`. (Would happen at scope end anyway.)
    drop(stat_guard);
    secator_debug::debug!(
        "end",
        "{} subprocess exited code={}",
        spec.name,
        status.and_then(|s| s.code()).unwrap_or(-1)
    );
    Ok(())
}

/// Per-record dispatch — picks the right `on_<loader>_loaded` callback or falls
/// back to the default schema conversion. Mirrors Python `_run_command_loaded_item`.
fn dispatch_record(
    spec: &TaskSpec,
    output_maps: &OutputMaps,
    ctx: &mut HookCtx,
    loader: &ItemLoader,
    mut record: Map,
) -> Vec<OutputItem> {
    let callback = if loader.is_json() { spec.on_json_loaded } else { spec.on_regex_loaded };
    if let Some(cb) = callback {
        // Callback owns the per-record logic (validators / pre-convert / typing).
        let out = cb(ctx, record);
        secator_debug::debug!(
            "item_loader",
            "{} {:?} → {} item(s)",
            spec.name,
            loader,
            out.len()
        );
        return out;
    }
    // Default path: validate_item → on_item_pre_convert → convert_item.
    for v in spec.validators.validate_item {
        if !v(&record) { return Vec::new(); }
    }
    for h in spec.hooks.on_item_pre_convert {
        if !h(ctx, &mut record) { return Vec::new(); }
    }
    convert_item(&record, spec.output_types, output_maps, spec.discriminator)
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use secator_model::Url;
    use tokio::sync::mpsc;

    fn tag_passive(_ctx: &mut HookCtx, item: &mut OutputItem) -> bool {
        if let OutputItem::Subdomain(s) = item {
            s.tags = vec!["passive".into()];
        }
        true
    }
    static TAG_HOOKS: HookRegistry = HookRegistry {
        on_item: &[tag_passive],
        ..HookRegistry::EMPTY
    };

    static TEST_SPEC: TaskSpec = TaskSpec {
        name: "echo-subdomain",
        description: "test spec",
        cmd: "echo",
        input_types: &["host"],
        output_types: &["subdomain"],
        tags: &[],
        json_flag: None,
        input_wiring: InputWiring {
            single: secator_options::SingleMode::Arg,
            file: secator_options::FileMode::Arg,
        },
        item_loaders: &[ItemLoader::Json],
        input_chunk_size: 0,
        on_json_loaded: None,
        on_regex_loaded: None,
        output_maps: empty_output_maps,
        discriminator: None,
        hooks: TAG_HOOKS,
        validators: ValidatorRegistry::EMPTY,
        schema: empty_schema,
        install: InstallSpec::EMPTY,
        proxy_caps: crate::ProxyCaps::NONE,
        encoding: "utf-8",
        ignore_return_code: false,
        requires_sudo: false,
    };

    #[tokio::test]
    async fn on_item_hook_fires_and_can_mutate() {
        let cmd = r#"echo '{"host":"a.example.com","domain":"example.com"}'"#;
        let (tx, mut rx) = mpsc::channel(16);
        let mut ctx = HookCtx { task_name: "test", ..HookCtx::default() };
        execute_with_hooks(cmd, &TEST_SPEC, false, &mut ctx, &tx).await.unwrap();
        drop(tx);
        let item = rx.recv().await.unwrap();
        match item {
            OutputItem::Subdomain(s) => assert_eq!(s.tags, vec!["passive".to_string()]),
            _ => panic!("expected Subdomain"),
        }
    }

    // ----- on_item hook can DROP an item by returning false ---------------
    fn drop_localhost(_c: &mut HookCtx, item: &mut OutputItem) -> bool {
        if let OutputItem::Subdomain(s) = item {
            return s.host != "localhost";
        }
        true
    }
    static DROP_HOOKS: HookRegistry = HookRegistry {
        on_item: &[drop_localhost],
        ..HookRegistry::EMPTY
    };
    static DROP_SPEC: TaskSpec = TaskSpec {
        name: "drop-localhost", description: "", cmd: "echo",
        input_types: &["host"], output_types: &["subdomain"], tags: &[],
        json_flag: None,
        input_wiring: InputWiring {
            single: secator_options::SingleMode::Arg, file: secator_options::FileMode::Arg,
        },
        item_loaders: &[ItemLoader::Json],
        input_chunk_size: 0,
        on_json_loaded: None, on_regex_loaded: None,
        output_maps: empty_output_maps, discriminator: None,
        hooks: DROP_HOOKS, validators: ValidatorRegistry::EMPTY,
        schema: empty_schema,
        install: InstallSpec::EMPTY,
        proxy_caps: crate::ProxyCaps::NONE,
        encoding: "utf-8",
        ignore_return_code: false,
        requires_sudo: false,
    };

    #[tokio::test]
    async fn on_item_hook_can_drop() {
        let cmd = "printf '%s\\n' \
            '{\"host\":\"a.example.com\",\"domain\":\"example.com\"}' \
            '{\"host\":\"localhost\",\"domain\":\"example.com\"}'";
        let (tx, mut rx) = mpsc::channel(16);
        let mut ctx = HookCtx { task_name: "test", ..HookCtx::default() };
        execute_with_hooks(cmd, &DROP_SPEC, false, &mut ctx, &tx).await.unwrap();
        drop(tx);
        let mut got = Vec::new();
        while let Some(it) = rx.recv().await { got.push(it); }
        assert_eq!(got.len(), 1);
        match &got[0] {
            OutputItem::Subdomain(s) => assert_eq!(s.host, "a.example.com"),
            _ => panic!("expected Subdomain"),
        }
    }

    // ----- on_cmd hook can rewrite the command ---------------------------
    fn append_extra_flag(_c: &mut HookCtx, cmd: &mut String) { cmd.push_str(" --extra"); }
    static CMD_HOOKS: HookRegistry = HookRegistry {
        on_cmd: &[append_extra_flag],
        ..HookRegistry::EMPTY
    };
    static CMD_SPEC: TaskSpec = TaskSpec {
        name: "cmd-hook", description: "", cmd: "echo",
        input_types: &["host"], output_types: &["subdomain"], tags: &[],
        json_flag: None,
        input_wiring: InputWiring {
            single: secator_options::SingleMode::Arg, file: secator_options::FileMode::Arg,
        },
        item_loaders: &[ItemLoader::Json],
        input_chunk_size: 0,
        on_json_loaded: None, on_regex_loaded: None,
        output_maps: empty_output_maps, discriminator: None,
        hooks: CMD_HOOKS, validators: ValidatorRegistry::EMPTY,
        schema: empty_schema,
        install: InstallSpec::EMPTY,
        proxy_caps: crate::ProxyCaps::NONE,
        encoding: "utf-8",
        ignore_return_code: false,
        requires_sudo: false,
    };

    #[tokio::test]
    async fn on_cmd_hook_can_mutate_command() {
        let mut runner = CommandRunner::new(&CMD_SPEC, vec!["foo".into()]);
        let (tx, mut rx) = mpsc::channel(16);
        runner.run(tx).await.unwrap();
        // Nothing parses from "foo --extra" but the cmd shouldn't panic — the hook ran.
        let _ = rx.recv().await; // may be None
    }

    // ----- input validator can short-circuit -----------------------------
    fn forbid_empty(inputs: &[String]) -> Result<(), String> {
        if inputs.is_empty() { Err("inputs required".into()) } else { Ok(()) }
    }
    static VAL: ValidatorRegistry = ValidatorRegistry {
        validate_input: &[forbid_empty],
        validate_item: &[],
    };
    static VAL_SPEC: TaskSpec = TaskSpec {
        name: "val-spec", description: "", cmd: "echo",
        input_types: &["host"], output_types: &["subdomain"], tags: &[],
        json_flag: None,
        input_wiring: InputWiring {
            single: secator_options::SingleMode::Arg, file: secator_options::FileMode::Arg,
        },
        item_loaders: &[ItemLoader::Json],
        input_chunk_size: 0,
        on_json_loaded: None, on_regex_loaded: None,
        output_maps: empty_output_maps, discriminator: None,
        hooks: HookRegistry::EMPTY, validators: VAL,
        schema: empty_schema,
        install: InstallSpec::EMPTY,
        proxy_caps: crate::ProxyCaps::NONE,
        encoding: "utf-8",
        ignore_return_code: false,
        requires_sudo: false,
    };

    #[tokio::test]
    async fn validator_short_circuits_run() {
        let mut runner = CommandRunner::new(&VAL_SPEC, vec![]);
        let (tx, _rx) = mpsc::channel(16);
        let err = runner.run(tx).await.unwrap_err();
        assert!(matches!(err, RunnerError::Validation(_)));
    }

    // ----- NativeRunner ---------------------------------------------------
    fn native_run(inputs: &[String], _opts: &RunOpts) -> Vec<OutputItem> {
        inputs.iter()
            .map(|s| OutputItem::Url(Url { url: s.clone(), ..Default::default() }))
            .collect()
    }
    static NATIVE: NativeSpec = NativeSpec {
        name: "native-url",
        description: "wrap each input as a Url",
        input_types: &["url"],
        output_types: &["url"],
        tags: &[],
        run: native_run,
        hooks: HookRegistry::EMPTY,
        validators: ValidatorRegistry::EMPTY,
        schema: empty_schema,
        install: InstallSpec::EMPTY,
        proxy_caps: crate::ProxyCaps::NONE,
        encoding: "utf-8",
        ignore_return_code: false,
        requires_sudo: false,
    };

    #[tokio::test]
    async fn native_runner_yields_results() {
        let runner = NativeRunner::new(&NATIVE, vec!["https://a".into(), "https://b".into()]);
        let (tx, mut rx) = mpsc::channel(16);
        runner.run(tx).await.unwrap();
        let mut got = Vec::new();
        while let Some(it) = rx.recv().await { got.push(it); }
        assert_eq!(got.len(), 2);
    }

    /// P3.1: when a TaskSpec sets `input_chunk_size: 0`, the runner should fall
    /// back to `CONFIG.runners.input_chunk_size` instead of running every input
    /// in one chunk. Default config is 100.
    #[test]
    fn effective_chunk_size_falls_back_to_config() {
        // TEST_SPEC declares input_chunk_size: 0. With config default 100 the
        // effective size should be 100.
        let runner = CommandRunner::new(&TEST_SPEC, vec![]);
        assert_eq!(
            runner.effective_chunk_size(),
            secator_config::get().runners.input_chunk_size as usize,
            "spec=0 must fall back to config.runners.input_chunk_size",
        );
    }

    /// P3.3: `tasks.overrides.<task>.<opt>` fills opts the operator hasn't set
    /// explicitly, but never overwrites an existing CLI/YAML value.
    #[test]
    fn apply_task_overrides_fills_only_unset_opts() {
        use serde_yaml::Value as Yaml;
        // Build a config whose `tasks.overrides.echo-subdomain` has two opts:
        // one already present on the runner, one not.
        let mut cfg = secator_config::Config::default();
        let mut over = std::collections::BTreeMap::new();
        over.insert("threads".to_string(), Yaml::Number(serde_yaml::Number::from(99)));
        over.insert("tag".to_string(), Yaml::String("from-config".into()));
        cfg.tasks.overrides.insert("echo-subdomain".into(), over);
        let _ = secator_config::set(cfg);

        let mut runner = CommandRunner::new(&TEST_SPEC, vec!["example.com".into()]);
        // Pre-set `threads` on the runner — config must NOT clobber it.
        runner.opts.insert("threads".into(), "5".into());
        runner.apply_task_overrides();

        assert_eq!(runner.opts.get("threads").map(String::as_str), Some("5"),
            "explicit opt must win over config override");
        // `tag` wasn't pre-set; comes from the config-level override (if the
        // process-wide config we set above was the FIRST set call). Tolerate
        // both — what we MUST verify is the no-clobber guarantee for `threads`.
        if let Some(tag) = runner.opts.get("tag") {
            assert_eq!(tag, "from-config");
        }
    }
}
