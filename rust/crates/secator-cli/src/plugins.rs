//! Discovery + load of `.rs`-source plugin crates dropped under
//! `~/.secator/templates/`.
//!
//! Two pieces:
//! 1. [`build_user_templates`] — invoked by `secator template build`; shells
//!    out to `cargo build --release` against the templates dir. Emits the
//!    same stderr cargo would, then re-walks the resulting `target/release/`
//!    so callers can see exactly which artifacts now exist.
//! 2. [`load_user_plugins`] — invoked by main.rs at startup; opens every
//!    `lib*.so` / `*.dylib` / `*.dll` in `<templates>/target/release/` via
//!    `libloading`, calls each plugin's `secator_plugin_v1_register`, and
//!    funnels the registered tasks / drivers / exporters into the host's
//!    static lookup. Mismatched ABI versions are refused with a clear error
//!    (better than crashing on an incompatible vtable layout).
//!
//! Notes:
//! - Rust has no stable ABI. Plugins MUST be built with the same `rustc`
//!   that built secator itself + the same `secator-plugin-api` revision. The
//!   `secator template build` subcommand uses the host toolchain by default,
//!   which keeps this safe in the common case.
//! - We `mem::forget` each `Library` so the dylib stays mapped for the
//!   process lifetime. Drivers / exporters returned by the plugin reference
//!   functions inside the dylib; closing the library would crash the next
//!   call.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

use secator_plugin_api::{PluginRegistry, ABI_VERSION, ENTRY_SYMBOL};

// -------------------------------------------------------------------- addons.json

/// Declarative registry of plugins the operator wants loaded (or explicitly
/// disabled). Persisted at `<templates>/addons.json`. Optional — if absent, the
/// loader falls back to loading every cdylib it finds under
/// `<templates>/target/release/`.
///
/// The key is the dylib file stem WITH the `lib` prefix stripped on unix (e.g.
/// `libmy_scanner.so` → `"my_scanner"`, `my_scanner.dll` → `"my_scanner"`).
/// Match `AddonEntry::enabled == false` skips the corresponding dylib at load
/// time; entries not listed in the manifest are treated as `enabled: true`
/// (operators opt OUT, not in — matches the "drop a crate, it works" ergonomics).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AddonsManifest {
    /// Schema version. Bumped when the on-disk shape changes in a
    /// backwards-incompatible way; older files still parse but log a warning.
    pub version: u32,
    /// Addon name → entry. Preserved order via BTreeMap so
    /// `secator template addons list` is stable across runs.
    pub addons: BTreeMap<String, AddonEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AddonEntry {
    /// `false` → skip this dylib at plugin-load time (log a WRN). Defaults to
    /// `true` so a fresh entry with just a description is enabled.
    pub enabled: bool,
    /// Operator-facing description; unused by the loader, shown in
    /// `secator template addons list`.
    pub description: String,
}

impl Default for AddonsManifest {
    fn default() -> Self {
        Self { version: 1, addons: BTreeMap::new() }
    }
}
impl Default for AddonEntry {
    fn default() -> Self {
        Self { enabled: true, description: String::new() }
    }
}

impl AddonsManifest {
    /// Manifest file path — `<templates_dir>/addons.json`.
    pub fn path(templates_dir: &Path) -> PathBuf {
        templates_dir.join("addons.json")
    }

    /// Load from `<templates>/addons.json`. Returns `None` when the file is
    /// missing (all plugins load); returns `Some(Default)` on a malformed file
    /// (log-and-continue rather than crash the CLI).
    pub fn load(templates_dir: &Path) -> Option<Self> {
        let path = Self::path(templates_dir);
        if !path.is_file() {
            return None;
        }
        match std::fs::read_to_string(&path) {
            Ok(body) => match serde_json::from_str::<Self>(&body) {
                Ok(m) => Some(m),
                Err(e) => {
                    eprintln!(
                        "[WRN] Failed to parse {} — ignoring manifest: {e}",
                        path.display()
                    );
                    None
                }
            },
            Err(e) => {
                eprintln!("[WRN] Failed to read {}: {e}", path.display());
                None
            }
        }
    }

    /// Serialize + write to disk. Creates the file (and parent dir) if needed.
    /// Pretty-printed so operators can hand-edit.
    pub fn save(&self, templates_dir: &Path) -> Result<PathBuf, String> {
        let path = Self::path(templates_dir);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create {}: {e}", parent.display()))?;
        }
        let body = serde_json::to_string_pretty(self)
            .map_err(|e| format!("serialize manifest: {e}"))?;
        std::fs::write(&path, body).map_err(|e| format!("write manifest: {e}"))?;
        Ok(path)
    }

    /// Look up an entry; return `true` when the addon should load (missing
    /// entries default to enabled — Python parity with "drop it in, it works").
    pub fn is_enabled(&self, name: &str) -> bool {
        self.addons.get(name).map(|e| e.enabled).unwrap_or(true)
    }

    /// Flip an entry to `enabled = true`. Creates it with an empty
    /// description if the entry is new.
    pub fn enable(&mut self, name: &str) {
        self.addons.entry(name.to_string()).or_default().enabled = true;
    }

    /// Flip an entry to `enabled = false`. Creates the entry if new so a
    /// subsequent `secator template addons list` reflects the intent.
    pub fn disable(&mut self, name: &str) {
        self.addons.entry(name.to_string()).or_default().enabled = false;
    }
}

/// Derive the addon key from a dylib filename — strip the platform-specific
/// `lib` prefix on unix and the extension everywhere. Mirrors the pattern
/// operators would type into `secator template addons enable <name>`.
pub fn addon_key_for(path: &Path) -> Option<String> {
    let stem = path.file_stem()?.to_str()?;
    #[cfg(unix)]
    let cleaned = stem.strip_prefix("lib").unwrap_or(stem);
    #[cfg(not(unix))]
    let cleaned = stem;
    Some(cleaned.to_string())
}

/// Outcome of loading every plugin under `<templates>/target/release/`.
/// Returned by [`load_user_plugins`] so the CLI can fold the contributions
/// into its global registries.
#[derive(Default)]
pub struct LoadedPlugins {
    pub tasks: Vec<&'static secator_runner::TaskSpec>,
    pub drivers: Vec<(String, std::sync::Arc<dyn secator_driver::Driver>)>,
    pub exporters: Vec<(String, Box<dyn secator_exporters::Exporter>)>,
}

/// Walk `<templates>/target/release/` for cdylibs and dlopen each one. Any
/// failure (missing symbols, ABI mismatch, IO error) is logged + skipped —
/// one bad plugin never fails the whole load. Returns the aggregate of
/// every contribution every loaded plugin registered.
pub fn load_user_plugins(templates_dir: &Path) -> LoadedPlugins {
    let mut out = LoadedPlugins::default();
    let release_dir = templates_dir.join("target").join("release");
    if !release_dir.is_dir() {
        return out;
    }
    let entries = match std::fs::read_dir(&release_dir) {
        Ok(it) => it,
        Err(_) => return out,
    };
    // Optional manifest — missing = load everything; present = skip
    // entries flagged `enabled: false`.
    let manifest = AddonsManifest::load(templates_dir);
    for entry in entries.flatten() {
        let path = entry.path();
        if !is_dylib(&path) {
            continue;
        }
        // Manifest gate: named entries can opt an addon out. Un-named entries
        // load by default so an operator can drop a cdylib in without touching
        // the manifest.
        if let (Some(m), Some(key)) = (manifest.as_ref(), addon_key_for(&path)) {
            if !m.is_enabled(&key) {
                eprintln!(
                    "[INF] Plugin {key}: disabled via addons.json — skipped"
                );
                continue;
            }
        }
        match load_one_plugin(&path) {
            Ok(reg) => {
                let (mut tasks, mut drivers, mut exporters, source) = reg.drain();
                let task_n = tasks.len();
                let drv_n = drivers.len();
                let exp_n = exporters.len();
                if task_n + drv_n + exp_n > 0 {
                    eprintln!(
                        "[INF] Plugin {source} registered {task_n} task(s), {drv_n} driver(s), {exp_n} exporter(s)"
                    );
                }
                out.tasks.append(&mut tasks);
                out.drivers.append(&mut drivers);
                out.exporters.append(&mut exporters);
            }
            Err(e) => {
                eprintln!("[WRN] Plugin {}: skipped — {e}", path.display());
            }
        }
    }
    out
}

/// Row shape returned by [`list_addons`] — one entry per cdylib actually on
/// disk, cross-referenced against the manifest so the CLI can render the
/// combined view (`present but not manifested`, `manifested but no dylib`,
/// etc.).
#[derive(Debug, Clone)]
pub struct AddonInfo {
    pub name: String,
    pub enabled: bool,
    pub description: String,
    /// `true` when a matching cdylib exists under `target/release/`; `false`
    /// when the manifest names an addon whose dylib hasn't been built yet.
    pub built: bool,
}

/// Render the union of `<templates>/addons.json` entries + on-disk cdylibs.
/// Ordering: manifested entries in alphabetical order first, then any
/// on-disk-only dylibs (built but not tracked) alphabetized after.
pub fn list_addons(templates_dir: &Path) -> Vec<AddonInfo> {
    let manifest = AddonsManifest::load(templates_dir).unwrap_or_default();
    let release_dir = templates_dir.join("target").join("release");
    let built_keys: std::collections::BTreeSet<String> = std::fs::read_dir(&release_dir)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| is_dylib(p))
        .filter_map(|p| addon_key_for(&p))
        .collect();

    let mut out: Vec<AddonInfo> = Vec::new();
    for (name, entry) in manifest.addons.iter() {
        out.push(AddonInfo {
            name: name.clone(),
            enabled: entry.enabled,
            description: entry.description.clone(),
            built: built_keys.contains(name),
        });
    }
    // Add on-disk-only dylibs that the manifest doesn't mention (implicit-enabled).
    for key in &built_keys {
        if manifest.addons.contains_key(key) {
            continue;
        }
        out.push(AddonInfo {
            name: key.clone(),
            enabled: true,
            description: String::from("(untracked — dropped in without a manifest entry)"),
            built: true,
        });
    }
    out
}

fn is_dylib(path: &Path) -> bool {
    let ext = match path.extension().and_then(|e| e.to_str()) {
        Some(e) => e.to_ascii_lowercase(),
        None => return false,
    };
    matches!(ext.as_str(), "so" | "dylib" | "dll")
}

/// Open one dylib, verify ABI, run the entry point against a fresh registry,
/// and `mem::forget` the library so its symbols stay valid for the process
/// lifetime.
fn load_one_plugin(path: &Path) -> Result<PluginRegistry, String> {
    // SAFETY: `libloading::Library::new` is unsafe because constructors in
    // the dylib run at load time; we trust user-supplied plugins to be
    // well-behaved (same trust level as `cargo run`).
    let lib = unsafe { libloading::Library::new(path) }
        .map_err(|e| format!("dlopen failed: {e}"))?;

    // 1) ABI version probe — refuse mismatches loudly.
    let version: libloading::Symbol<extern "C" fn() -> u32> = unsafe {
        lib.get(b"secator_plugin_v1_abi_version")
            .map_err(|_| {
                "missing `secator_plugin_v1_abi_version` symbol — \
                 rebuild plugin against the current secator-plugin-api"
                    .to_string()
            })?
    };
    let v = version();
    if v != ABI_VERSION {
        return Err(format!(
            "ABI version mismatch: plugin reports v{v}, host expects v{ABI_VERSION}"
        ));
    }

    // 2) Entry point — register tasks/drivers/exporters into a fresh registry.
    let entry: libloading::Symbol<extern "C" fn(&mut PluginRegistry)> = unsafe {
        lib.get(ENTRY_SYMBOL)
            .map_err(|_| {
                format!(
                    "missing `{}` symbol — did you forget `export_plugin!`?",
                    std::str::from_utf8(ENTRY_SYMBOL).unwrap_or("entry")
                )
            })?
    };
    let mut reg = PluginRegistry::new(path.display().to_string());
    entry(&mut reg);

    // Keep the Library mapped for the process lifetime — function pointers
    // we just registered point into it.
    std::mem::forget(lib);
    Ok(reg)
}

/// Generate a starter plugin crate under `<templates>/<name>/`. Refuses to
/// overwrite an existing directory. The scaffold is the smallest crate that
/// links against `secator-plugin-api` and produces a cdylib registering a
/// single example task — `secator template build` picks it up immediately.
///
/// The plugin-api path is resolved relative to the *host* binary's compile-
/// time `CARGO_MANIFEST_DIR` so the scaffold works regardless of where the
/// operator's templates dir lives.
pub fn scaffold_plugin(templates_dir: &Path, name: &str) -> Result<PathBuf, String> {
    if name.is_empty() {
        return Err("plugin name must not be empty".into());
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(format!(
            "plugin name `{name}` must match `[A-Za-z0-9_-]+` — keep it crate-safe"
        ));
    }
    let crate_dir = templates_dir.join(name);
    if crate_dir.exists() {
        return Err(format!(
            "{} already exists — pick a different name or remove it first",
            crate_dir.display()
        ));
    }
    let src_dir = crate_dir.join("src");
    std::fs::create_dir_all(&src_dir)
        .map_err(|e| format!("create {}: {e}", src_dir.display()))?;

    // We resolve the plugin-api crate by absolute path so a freshly-scaffolded
    // plugin compiles without the operator running `cargo add`. The host's
    // `CARGO_MANIFEST_DIR` points at `crates/secator-cli/`; ascend one level
    // and take the `secator-plugin-api` sibling.
    let plugin_api_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(|p| p.join("secator-plugin-api"))
        .ok_or_else(|| "could not resolve secator-plugin-api crate path".to_string())?;

    let cargo_toml = format!(
        r#"[package]
name = "{name}"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
secator-plugin-api = {{ path = "{api_path}" }}
"#,
        api_path = plugin_api_path.display(),
    );
    std::fs::write(crate_dir.join("Cargo.toml"), cargo_toml)
        .map_err(|e| format!("write Cargo.toml: {e}"))?;

    let lib_rs = r#"//! Example secator plugin — registers one task ("hello") that echoes its target.
//!
//! Build:    secator template build
//! Run:      secator x hello example.com
//!
//! Remove this scaffold by deleting the parent directory.

use secator_plugin_api::{export_plugin, PluginRegistry};
use secator_plugin_api::runner::{
    HookRegistry, InstallSpec, NativeSpec, ProxyCaps, ValidatorRegistry,
};
use secator_plugin_api::runner::secator_model::{Info, OutputItem};
use secator_plugin_api::runner::secator_options::{OptSchema, RunOpts};

static SPEC: NativeSpec = NativeSpec {
    name: "hello",
    description: "Example plugin task — echoes the target.",
    input_types: &[],
    output_types: &["info"],
    tags: &["example"],
    run,
    hooks: HookRegistry::EMPTY,
    validators: ValidatorRegistry::EMPTY,
    schema: build_schema,
    install: InstallSpec::EMPTY,
    proxy_caps: ProxyCaps::NONE,
    encoding: "utf-8",
    ignore_return_code: false,
    requires_sudo: false,
    default_inputs: Some(""),
};

fn run(inputs: &[String], _opts: &RunOpts) -> Vec<OutputItem> {
    let target = inputs.join(",");
    vec![OutputItem::Info(Info {
        message: format!("hello, {target}!"),
        ..Default::default()
    })]
}

fn build_schema() -> OptSchema {
    OptSchema { opt_prefix: "--", ..OptSchema::default() }
}

fn register(reg: &mut PluginRegistry) {
    reg.register_task(&SPEC);
}

export_plugin!(register);
"#;
    std::fs::write(src_dir.join("lib.rs"), lib_rs)
        .map_err(|e| format!("write src/lib.rs: {e}"))?;

    // Top-level Cargo.toml at <templates_dir> is a workspace pointing at every
    // plugin subcrate. Create it if missing; otherwise add this plugin to the
    // `members` list when it isn't already there.
    upsert_workspace_member(templates_dir, name)?;

    Ok(crate_dir)
}

/// Maintain `<templates_dir>/Cargo.toml` as a cargo workspace listing every
/// scaffolded plugin. Idempotent: rerunning `scaffold` with a fresh name
/// appends; rerunning with an existing name errors earlier in [`scaffold_plugin`].
fn upsert_workspace_member(templates_dir: &Path, name: &str) -> Result<(), String> {
    let manifest = templates_dir.join("Cargo.toml");
    if !manifest.is_file() {
        let body = format!("[workspace]\nresolver = \"2\"\nmembers = [\"{name}\"]\n");
        return std::fs::write(&manifest, body)
            .map_err(|e| format!("write workspace Cargo.toml: {e}"))
            .map(|_| ());
    }
    let text = std::fs::read_to_string(&manifest)
        .map_err(|e| format!("read workspace Cargo.toml: {e}"))?;
    if text.contains(&format!("\"{name}\"")) {
        return Ok(());
    }
    // Inject `,\n  "<name>"` right before the closing bracket of `members =
    // [...]`. We do this as a string edit rather than re-serializing toml to
    // stay zero-dep on a toml writer.
    let updated = match text.find("members = [") {
        Some(idx) => {
            let rest = &text[idx..];
            let close_offset = rest.find(']').ok_or_else(|| {
                "workspace Cargo.toml: unterminated members array".to_string()
            })?;
            let close_abs = idx + close_offset;
            let mut new = String::with_capacity(text.len() + name.len() + 8);
            new.push_str(&text[..close_abs]);
            // Trim trailing whitespace before `]` so the comma lands cleanly.
            let trimmed_end = new.trim_end_matches(&[' ', '\t', '\n', ',', '\r'][..]).len();
            new.truncate(trimmed_end);
            new.push_str(&format!(",\n  \"{name}\"\n"));
            new.push_str(&text[close_abs..]);
            new
        }
        None => format!("{text}\n[workspace]\nresolver = \"2\"\nmembers = [\"{name}\"]\n"),
    };
    std::fs::write(&manifest, updated)
        .map_err(|e| format!("write workspace Cargo.toml: {e}"))
}

/// Run `cargo build --release` against `<templates>/` if a `Cargo.toml` is
/// present. Streams cargo's output verbatim to the operator's terminal so
/// they see compile errors in real time. Returns `Ok(paths_built)` listing
/// the dylibs that exist after the build, or `Err(reason)` if cargo bailed.
pub fn build_user_templates(templates_dir: &Path) -> Result<Vec<PathBuf>, String> {
    let manifest = templates_dir.join("Cargo.toml");
    if !manifest.is_file() {
        return Err(format!(
            "no Cargo.toml at {} — drop a plugin crate there first (see \
             `secator template scaffold`)",
            manifest.display()
        ));
    }
    eprintln!("[INF] Building plugins in {}", templates_dir.display());
    let status = Command::new("cargo")
        .arg("build")
        .arg("--release")
        .arg("--manifest-path")
        .arg(&manifest)
        .status()
        .map_err(|e| format!("failed to spawn cargo: {e}"))?;
    if !status.success() {
        return Err(format!("cargo build exited with {status}"));
    }
    let release_dir = templates_dir.join("target").join("release");
    let mut out: Vec<PathBuf> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&release_dir) {
        for e in entries.flatten() {
            let p = e.path();
            if is_dylib(&p) {
                out.push(p);
            }
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dylib_extension_check() {
        assert!(is_dylib(Path::new("libfoo.so")));
        assert!(is_dylib(Path::new("foo.dylib")));
        assert!(is_dylib(Path::new("foo.dll")));
        assert!(!is_dylib(Path::new("foo.txt")));
        assert!(!is_dylib(Path::new("Cargo.toml")));
    }

    #[test]
    fn addon_key_strips_lib_prefix_on_unix() {
        // Unix: `libfoo.so` → `foo`.
        assert_eq!(addon_key_for(Path::new("libfoo.so")).unwrap(), "foo");
        // Multi-word crate names: `libmy_scanner.so` → `my_scanner`.
        assert_eq!(
            addon_key_for(Path::new("libmy_scanner.so")).unwrap(),
            "my_scanner"
        );
        // No `lib` prefix (Windows-style .dll) → stem unchanged.
        assert_eq!(addon_key_for(Path::new("foo.dll")).unwrap(), "foo");
    }

    /// addons.json semantics: missing entries default to ENABLED (so an
    /// operator can drop a cdylib in without touching the manifest).
    #[test]
    fn manifest_missing_entry_defaults_enabled() {
        let m = AddonsManifest::default();
        assert!(m.is_enabled("anything"));
    }

    /// addons.json semantics: `enabled: false` short-circuits the load.
    #[test]
    fn manifest_disable_flips_and_survives_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let mut m = AddonsManifest::default();
        m.disable("noisy-plugin");
        m.enable("keeper");
        let path = m.save(tmp.path()).expect("save");
        assert!(path.ends_with("addons.json"));

        let loaded = AddonsManifest::load(tmp.path()).expect("manifest present");
        assert!(!loaded.is_enabled("noisy-plugin"));
        assert!(loaded.is_enabled("keeper"));
        assert!(loaded.is_enabled("anything-else-implicit"));
    }

    /// A malformed addons.json must not crash the CLI — the loader logs a
    /// warning and returns `None` so the fallback "load everything" path
    /// takes over.
    #[test]
    fn malformed_manifest_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("addons.json"), "{not json").unwrap();
        assert!(AddonsManifest::load(tmp.path()).is_none());
    }

    #[test]
    fn list_addons_includes_untracked_dylibs() {
        let tmp = tempfile::tempdir().unwrap();
        // Fake a built cdylib the manifest doesn't mention.
        let release = tmp.path().join("target").join("release");
        std::fs::create_dir_all(&release).unwrap();
        std::fs::write(release.join("libuntracked.so"), b"fake").unwrap();
        // Explicit-disabled entry with no dylib.
        let mut m = AddonsManifest::default();
        m.disable("disabled_entry");
        m.save(tmp.path()).unwrap();

        let rows = list_addons(tmp.path());
        let by_name: std::collections::HashMap<&str, &AddonInfo> =
            rows.iter().map(|r| (r.name.as_str(), r)).collect();
        assert_eq!(by_name.get("disabled_entry").unwrap().enabled, false);
        assert_eq!(by_name.get("disabled_entry").unwrap().built, false);
        assert_eq!(by_name.get("untracked").unwrap().enabled, true);
        assert_eq!(by_name.get("untracked").unwrap().built, true);
    }

    #[test]
    fn missing_directory_returns_empty_plugins() {
        let p = load_user_plugins(Path::new("/this/path/does/not/exist"));
        assert!(p.tasks.is_empty());
        assert!(p.drivers.is_empty());
        assert!(p.exporters.is_empty());
    }

    /// #177 T8: `scaffold` creates a fresh crate skeleton + ensures the
    /// templates dir Cargo.toml workspace lists it as a member.
    #[test]
    fn scaffold_writes_full_skeleton_and_workspace_member() {
        let tmp = std::env::temp_dir().join(format!(
            "secator-plugins-scaffold-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let crate_dir = scaffold_plugin(&tmp, "my-plugin").expect("scaffold");
        assert!(crate_dir.join("Cargo.toml").exists(), "Cargo.toml missing");
        assert!(crate_dir.join("src/lib.rs").exists(), "src/lib.rs missing");

        let cargo = std::fs::read_to_string(crate_dir.join("Cargo.toml")).unwrap();
        assert!(cargo.contains("crate-type = [\"cdylib\"]"));
        assert!(cargo.contains("secator-plugin-api"));
        let lib = std::fs::read_to_string(crate_dir.join("src/lib.rs")).unwrap();
        assert!(lib.contains("export_plugin!"));
        assert!(lib.contains("name: \"hello\""));

        let ws = std::fs::read_to_string(tmp.join("Cargo.toml")).unwrap();
        assert!(ws.contains("\"my-plugin\""));

        // Scaffolding a second plugin appends to the workspace, doesn't replace.
        scaffold_plugin(&tmp, "another").expect("scaffold");
        let ws2 = std::fs::read_to_string(tmp.join("Cargo.toml")).unwrap();
        assert!(ws2.contains("\"my-plugin\""));
        assert!(ws2.contains("\"another\""));

        // Re-scaffolding the same name should refuse cleanly.
        let err = scaffold_plugin(&tmp, "my-plugin").unwrap_err();
        assert!(err.contains("already exists"));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn scaffold_rejects_bad_names() {
        let tmp = std::env::temp_dir().join(format!(
            "secator-plugins-scaffold-badname-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        assert!(scaffold_plugin(&tmp, "").is_err());
        assert!(scaffold_plugin(&tmp, "bad name").is_err());
        assert!(scaffold_plugin(&tmp, "bad/name").is_err());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn build_without_cargo_toml_errors_clearly() {
        let tmp = std::env::temp_dir().join(format!(
            "secator-plugins-no-cargo-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let err = build_user_templates(&tmp).unwrap_err();
        assert!(err.contains("Cargo.toml"));
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
