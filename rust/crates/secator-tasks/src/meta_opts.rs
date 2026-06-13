//! Shared meta-options (the canonical HTTP/recon set).
//!
//! Maps to Python `secator/tasks/_categories.py` `OPTS` registry. Defined once here and
//! referenced by every task's schema builder so we get consistent CLI flag names,
//! defaults, and help text across the catalog.
//!
//! The canonical name is the Python style (snake_case). Each task's `opt_key_map`
//! decides which CLI flag the tool actually expects (e.g. canonical `rate_limit` →
//! `--rate-limit` for httpx but `-rate-limit` for subfinder — same name, different
//! prefix from the spec's `opt_prefix`).

use secator_options::{OptSpec, OptType, Transform};

// ----------------------------------------------------------------- HTTP options

pub const HEADER: OptSpec = OptSpec {
    name: "header",
    ty: OptType::Str,
    short: Some("H"),
    is_flag: false,
    default: None,
    help: "Custom header to add to each request (KEY:VALUE)",
    internal: false,
    requires_sudo: false,
    shlex: true,
    pre_process: None,
    process: None,
};

pub const DELAY: OptSpec = OptSpec {
    name: "delay",
    ty: OptType::Float,
    short: Some("d"),
    is_flag: false,
    default: None,
    help: "Delay between requests (seconds)",
    internal: false,
    requires_sudo: false,
    shlex: true,
    pre_process: None,
    process: None,
};

pub const FOLLOW_REDIRECT: OptSpec = OptSpec {
    name: "follow_redirect",
    ty: OptType::Bool,
    short: None,
    is_flag: true,
    default: None,
    help: "Follow HTTP redirects",
    internal: false,
    requires_sudo: false,
    shlex: true,
    pre_process: None,
    process: None,
};

pub const METHOD: OptSpec = OptSpec {
    name: "method",
    ty: OptType::Str,
    short: Some("X"),
    is_flag: false,
    default: None,
    help: "HTTP method (GET/POST/PUT/...)",
    internal: false,
    requires_sudo: false,
    shlex: true,
    pre_process: None,
    process: None,
};

pub const PROXY: OptSpec = OptSpec {
    name: "proxy",
    ty: OptType::Str,
    short: None,
    is_flag: false,
    default: None,
    help: "HTTP(s) / SOCKS5 proxy",
    internal: false,
    requires_sudo: false,
    shlex: true,
    pre_process: None,
    process: None,
};

pub const RATE_LIMIT: OptSpec = OptSpec {
    name: "rate_limit",
    ty: OptType::Int,
    short: None,
    is_flag: false,
    default: None,
    help: "Max requests per second",
    internal: false,
    requires_sudo: false,
    shlex: true,
    pre_process: None,
    process: None,
};

pub const RETRIES: OptSpec = OptSpec {
    name: "retries",
    ty: OptType::Int,
    short: None,
    is_flag: false,
    default: None,
    help: "Number of retries on failure",
    internal: false,
    requires_sudo: false,
    shlex: true,
    pre_process: None,
    process: None,
};

pub const THREADS: OptSpec = OptSpec {
    name: "threads",
    ty: OptType::Int,
    short: None,
    is_flag: false,
    default: Some("50"),
    help: "Number of threads",
    internal: false,
    requires_sudo: false,
    shlex: true,
    pre_process: None,
    process: None,
};

pub const TIMEOUT: OptSpec = OptSpec {
    name: "timeout",
    ty: OptType::Int,
    short: None,
    is_flag: false,
    default: None,
    help: "Request timeout (seconds)",
    internal: false,
    requires_sudo: false,
    shlex: true,
    pre_process: None,
    process: None,
};

pub const USER_AGENT: OptSpec = OptSpec {
    name: "user_agent",
    ty: OptType::Str,
    short: None,
    is_flag: false,
    default: None,
    help: "Override the User-Agent header",
    internal: false,
    requires_sudo: false,
    shlex: true,
    pre_process: None,
    process: None,
};

pub const DATA: OptSpec = OptSpec {
    name: "data",
    ty: OptType::Str,
    short: None,
    is_flag: false,
    default: None,
    help: "Request body data",
    internal: false,
    requires_sudo: false,
    shlex: true,
    pre_process: None,
    process: None,
};

/// Canonical `output_path` meta opt — Python `definitions.OUTPUT_PATH`. Tasks
/// that write results to a file (dirsearch, nmap, arjun, …) accept this opt to
/// let the operator override where the artifact lands. The tool flag itself is
/// task-specific (`-oX` for nmap, `-o` for dirsearch, etc.) so each task pairs
/// this entry with `KeyMap::NotSupported` (to suppress flag emission) plus a
/// `before_init` hook that injects the right flag for that tool. The opt stays
/// `internal: false` so it shows up in --help and the CLI can collect a value.
pub const OUTPUT_PATH: OptSpec = OptSpec {
    name: "output_path",
    ty: OptType::Str,
    short: None,
    is_flag: false,
    default: None,
    help: "Override the output artifact path (default: <reports>/.outputs/<fqn>.<ext>)",
    internal: false,
    requires_sudo: false,
    shlex: true,
    pre_process: None,
    process: None,
};

// ----------------------------------------------------------------- Option groups

/// Shared HTTP base opts (Python `OPTS_HTTP_BASE`).
pub fn opts_http_base() -> Vec<OptSpec> {
    vec![
        HEADER, DELAY, FOLLOW_REDIRECT, METHOD, PROXY, RATE_LIMIT,
        RETRIES, THREADS, TIMEOUT, USER_AGENT, DATA,
    ]
}

/// Shared recon opts (Python `OPTS_RECON`).
pub fn opts_recon() -> Vec<OptSpec> {
    vec![DELAY, PROXY, RATE_LIMIT, RETRIES, THREADS, TIMEOUT]
}

// ----------------------------------------------------------------- Value transforms

/// Strip `http://` / `https://` from a proxy value (Python subfinder
/// `opt_value_map[PROXY]`).
pub fn proxy_strip_scheme(v: &str) -> Option<String> {
    let stripped = v
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    Some(stripped.to_string())
}

/// Allow callers to construct an `Option<Transform>` field-typed value at the use site.
pub const PROXY_STRIP: Transform = proxy_strip_scheme;

/// Join a list-shaped value as `a,b,c` (Python nuclei `opt_value_map` lambdas). The
/// option engine already serializes via `Display`; this helper expects values that
/// arrived as `[a, b, c]` style strings from the CLI (`a,b,c`) and is a no-op for
/// already-joined values — list parsing happens earlier in the option pipeline.
pub fn join_comma(v: &str) -> Option<String> {
    Some(v.to_string())
}

pub const LIST_JOIN_COMMA: Transform = join_comma;

// ----------------------------------------------------------- Config-derived defaults

/// Leak a `String` to obtain `&'static str` for use as an `OptSpec.default`. Called once
/// per opt at startup; memory cost negligible.
fn leak_default(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

/// Patch defaults on the supplied opts using process-wide [`secator_config`]. Mirrors
/// the Python config-defaults flow (`CONFIG.runners.threads`, `CONFIG.http.default_header`,
/// `CONFIG.http.response_max_size_bytes`).
///
/// Idempotent — only overrides when the opt name matches a config-linked key, and
/// preserves whatever was set if the relevant config field is empty.
pub fn apply_config_defaults(opts: &mut [OptSpec]) {
    let config = secator_config::get();
    for opt in opts.iter_mut() {
        match opt.name {
            "header" if !config.http.default_header.is_empty() => {
                opt.default = Some(leak_default(config.http.default_header.clone()));
            }
            "threads" => {
                opt.default = Some(leak_default(config.runners.threads.to_string()));
            }
            "rstr" | "rsts" => {
                opt.default = Some(leak_default(config.http.response_max_size_bytes.to_string()));
            }
            _ => {}
        }
    }
}
