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

use std::path::{Path, PathBuf};
use std::process::Command;

use secator_plugin_api::{PluginRegistry, ABI_VERSION, ENTRY_SYMBOL};

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
    for entry in entries.flatten() {
        let path = entry.path();
        if !is_dylib(&path) {
            continue;
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
