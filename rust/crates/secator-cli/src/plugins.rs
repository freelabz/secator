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
