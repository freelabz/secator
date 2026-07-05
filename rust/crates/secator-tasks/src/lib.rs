//! Built-in tool integrations.
//!
//! Maps to Python `secator/tasks/`. Built-ins are Rust values: a declarative `TaskSpec`
//! (defined in `secator-runner`) with `item_loaders` + Python-shaped callbacks
//! (`on_json_loaded` / `on_regex_loaded`) ported 1:1 from the Python task class so
//! migrating users find the hook names they know. MVP set (M2): subfinder, httpx;
//! nmap and nuclei in M3/M4. See `../docs/rewrite/04-task-integration.md`.

pub use secator_runner::{NativeSpec, TaskSpec};

pub mod native;

pub mod arjun;
pub mod arp;
pub mod arpscan;
pub mod bbot;
pub mod bup;
pub mod cariddi;
pub mod dalfox;
pub mod dirsearch;
pub mod dnsx;
pub mod feroxbuster;
pub mod ffuf;
pub mod fping;
pub mod gau;
pub mod getasn;
pub mod gf;
pub mod gitleaks;
pub mod gospider;
pub mod grype;
pub mod h8mail;
pub mod http_utils;
pub mod httpx;
pub mod jswhois;
pub mod katana;
pub mod maigret;
pub mod mapcidr;
pub mod meta_opts;
pub mod msfconsole;
pub mod naabu;
pub mod nmap;
pub mod nuclei;
pub mod ph;
pub mod search_vulns;
pub mod searchsploit;
pub mod sshaudit;
pub mod subfinder;
pub mod testssl;
pub mod trivy;
pub mod trufflehog;
pub mod urlfinder;
pub mod wafw00f;
pub mod whois;
pub mod whoisdomain;
pub mod wpprobe;
pub mod wpscan;
pub mod x8;
pub mod xurlfind3r;

/// Process-wide append slot for plugin-supplied TaskSpecs (set once at
/// startup by `secator-cli::plugins::load_user_plugins`). `all()` reads this
/// after the built-in list so plugin tasks show up in every lookup and
/// every clap subcommand without touching the built-in slice.
static PLUGIN_TASKS: std::sync::OnceLock<Vec<&'static TaskSpec>> = std::sync::OnceLock::new();

/// Same shape as `PLUGIN_TASKS` but for plugin-supplied `NativeSpec`s
/// (pure-Rust in-process tasks). Populated by
/// `secator-cli::plugins::load_user_plugins`.
static PLUGIN_NATIVE_TASKS: std::sync::OnceLock<Vec<&'static NativeSpec>> =
    std::sync::OnceLock::new();

/// One-shot installer for plugin TaskSpecs. Called by the CLI's plugin
/// loader at startup; idempotent thanks to OnceLock.
pub fn register_plugin_tasks(specs: Vec<&'static TaskSpec>) {
    let _ = PLUGIN_TASKS.set(specs);
}

/// One-shot installer for plugin NativeSpecs. Called by the CLI's plugin
/// loader at startup; idempotent thanks to OnceLock.
pub fn register_plugin_native_tasks(specs: Vec<&'static NativeSpec>) {
    let _ = PLUGIN_NATIVE_TASKS.set(specs);
}

/// All built-in task SPECs (plus any plugin-registered specs) in one slice —
/// used by the CLI to enumerate and dispatch.
pub fn all() -> Vec<&'static TaskSpec> {
    let mut v = built_in_specs();
    if let Some(extra) = PLUGIN_TASKS.get() {
        for s in extra {
            v.push(*s);
        }
    }
    v
}

fn built_in_specs() -> Vec<&'static TaskSpec> {
    vec![
        &subfinder::SPEC,
        &arjun::SPEC,
        &arp::SPEC,
        &arpscan::SPEC,
        &bbot::SPEC,
        &bup::SPEC,
        &cariddi::SPEC,
        &dalfox::SPEC,
        &dirsearch::SPEC,
        &dnsx::SPEC,
        &feroxbuster::SPEC,
        &ffuf::SPEC,
        &fping::SPEC,
        &gau::SPEC,
        &getasn::SPEC,
        &gf::SPEC,
        &gitleaks::SPEC,
        &gospider::SPEC,
        &grype::SPEC,
        &h8mail::SPEC,
        &httpx::SPEC,
        &jswhois::SPEC,
        &katana::SPEC,
        &maigret::SPEC,
        &mapcidr::SPEC,
        &msfconsole::SPEC,
        &naabu::SPEC,
        &nmap::SPEC,
        &nuclei::SPEC,
        &ph::SPEC,
        &sshaudit::SPEC,
        &search_vulns::SPEC,
        &searchsploit::SPEC,
        &testssl::SPEC,
        &trivy::SPEC,
        &trufflehog::SPEC,
        &urlfinder::SPEC,
        &wafw00f::SPEC,
        &whois::SPEC,
        &whoisdomain::SPEC,
        &wpprobe::SPEC,
        &wpscan::SPEC,
        &x8::SPEC,
        &xurlfind3r::SPEC,
    ]
}

/// Just the names (for the previous scaffold API).
pub fn registry() -> Vec<&'static str> {
    all().iter().map(|s| s.name).collect()
}

/// Look a task SPEC up by name.
pub fn get(name: &str) -> Option<&'static TaskSpec> {
    all().into_iter().find(|s| s.name == name)
}

/// All native (in-process) specs — built-ins + any plugin-registered ones.
pub fn native_all() -> Vec<&'static NativeSpec> {
    let mut v = native::all();
    if let Some(extra) = PLUGIN_NATIVE_TASKS.get() {
        for s in extra {
            v.push(*s);
        }
    }
    v
}

/// Look a native spec up by name (checks built-ins first, then plugins).
pub fn get_native(name: &str) -> Option<&'static NativeSpec> {
    if let Some(s) = native::get(name) {
        return Some(s);
    }
    PLUGIN_NATIVE_TASKS.get().and_then(|v| v.iter().copied().find(|s| s.name == name))
}

/// Union of every built-in task class name (command + native). Used by the CLI
/// to register subcommands without caring which runner backs each name.
pub fn all_names() -> Vec<&'static str> {
    let mut v: Vec<&'static str> = all().iter().map(|s| s.name).collect();
    v.extend(native_all().iter().map(|s| s.name));
    v
}
