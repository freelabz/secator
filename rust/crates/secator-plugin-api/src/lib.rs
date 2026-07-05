//! Stable surface for `~/.secator/templates/` plugin crates.
//!
//! Operators drop `.rs` files (or a whole Cargo crate) under
//! `~/.secator/templates/` that depend on THIS crate and export an
//! `extern "C" fn secator_plugin_v1_register(reg: &mut PluginRegistry)`. The
//! secator binary builds those crates as `cdylib`s, dlopens them at startup,
//! and calls the entry point so the plugin can register tasks, drivers, and
//! exporters into the live runtime.
//!
//! ## Rust ABI caveat
//!
//! Rust has no stable ABI. Plugins MUST be compiled with the same `rustc`
//! version + the same `secator-plugin-api` revision as the host binary.
//! `secator template build` invokes `cargo build --release` from the same
//! toolchain the host was built with, which keeps this safe in the common
//! case. Mismatched toolchains may produce mysterious runtime crashes — the
//! host emits a startup warning when it detects an obvious version skew (e.g.
//! missing `secator_plugin_api_VERSION` symbol).
//!
//! ## Minimal plugin skeleton
//!
//! ```ignore
//! use secator_plugin_api::{export_plugin, PluginRegistry};
//! use secator_plugin_api::runner::{...};
//!
//! static MY_TASK: TaskSpec = TaskSpec { /* ... */ };
//!
//! fn register(reg: &mut PluginRegistry) {
//!     reg.register_task(&MY_TASK);
//! }
//!
//! export_plugin!(register);
//! ```

use std::sync::Arc;

pub use secator_driver as driver;
pub use secator_exporters as exporters;
pub use secator_model as model;
pub use secator_options as options;
pub use secator_report as report;
pub use secator_runner as runner;

use secator_driver::Driver;
use secator_exporters::Exporter;
use secator_runner::{NativeSpec, TaskSpec};

/// Symbol the host looks up via `libloading::Library::get`. Plugins must
/// export `extern "C" fn secator_plugin_v1_register(&mut PluginRegistry)`;
/// the [`export_plugin!`] macro generates the boilerplate.
pub const ENTRY_SYMBOL: &[u8] = b"secator_plugin_v1_register";

/// Version of the plugin ABI. Bump on any breaking change to
/// [`PluginRegistry`]. The host checks the plugin's exported
/// `secator_plugin_v1_abi_version` symbol against this and refuses to load
/// mismatched plugins.
pub const ABI_VERSION: u32 = 1;

/// Sink the plugin uses to register its contributions during load. Held
/// mutably by the host loader and passed to the plugin's entry point.
pub struct PluginRegistry {
    pub(crate) tasks: Vec<&'static TaskSpec>,
    pub(crate) native_tasks: Vec<&'static NativeSpec>,
    pub(crate) drivers: Vec<(String, Arc<dyn Driver>)>,
    pub(crate) exporters: Vec<(String, Box<dyn Exporter>)>,
    pub(crate) source: String,
}

impl PluginRegistry {
    /// Build an empty registry tagged with the plugin's filesystem path so
    /// the host can surface "plugin X registered Y" lines at startup.
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            tasks: Vec::new(),
            native_tasks: Vec::new(),
            drivers: Vec::new(),
            exporters: Vec::new(),
            source: source.into(),
        }
    }

    /// Add a `&'static TaskSpec` (subprocess-wrapping task) to the global
    /// task registry. The spec must outlive the process; plugins typically
    /// declare a `static` at module scope. After the host pulls these out it
    /// appends them to its `StaticLookup` so `secator x <name>` resolves the
    /// plugin task.
    pub fn register_task(&mut self, spec: &'static TaskSpec) {
        self.tasks.push(spec);
    }

    /// Add a `&'static NativeSpec` — a pure-Rust in-process task (no
    /// subprocess). Same lifetime requirement as [`register_task`]. Use this
    /// when your plugin's logic runs entirely in Rust (`arp`, `ai`, custom
    /// business logic) — no need to spin up an external CLI just to shim it.
    pub fn register_native_task(&mut self, spec: &'static NativeSpec) {
        self.native_tasks.push(spec);
    }

    /// Add a driver under a stable name (used by `addons.<name>.enabled`).
    /// The driver value is held in an `Arc` so the host can clone it into
    /// the receive loop's driver fan-out.
    pub fn register_driver(&mut self, name: impl Into<String>, driver: Arc<dyn Driver>) {
        self.drivers.push((name.into(), driver));
    }

    /// Add an exporter. `name` is the stable identifier the user puts in
    /// `tasks.exporters`/`workflows.exporters`/`scans.exporters` config keys.
    pub fn register_exporter(&mut self, name: impl Into<String>, exporter: Box<dyn Exporter>) {
        self.exporters.push((name.into(), exporter));
    }

    /// Move the collected contributions out of the registry. Called by the
    /// host once the plugin's entry point has returned; the empty registry
    /// is then dropped. Order of tuple elements is stable across releases —
    /// pattern-match by position at the call site.
    pub fn drain(
        self,
    ) -> (
        Vec<&'static TaskSpec>,
        Vec<&'static NativeSpec>,
        Vec<(String, Arc<dyn Driver>)>,
        Vec<(String, Box<dyn Exporter>)>,
        String,
    ) {
        (self.tasks, self.native_tasks, self.drivers, self.exporters, self.source)
    }
}

/// Generate the `extern "C"` exports the host looks for on a freshly opened
/// dylib. Wraps a `fn(&mut PluginRegistry)` registration callback. Use this
/// once per plugin crate.
#[macro_export]
macro_rules! export_plugin {
    ($register:ident) => {
        /// ABI version probe. The host reads this symbol before calling
        /// `secator_plugin_v1_register`; a mismatch makes it refuse the load
        /// with a clear error instead of crashing on an incompatible
        /// vtable layout.
        #[no_mangle]
        pub extern "C" fn secator_plugin_v1_abi_version() -> u32 {
            $crate::ABI_VERSION
        }

        /// Plugin entry point — the host hands us a mutable PluginRegistry
        /// and we register every task / driver / exporter we want surfaced.
        #[no_mangle]
        pub extern "C" fn secator_plugin_v1_register(reg: &mut $crate::PluginRegistry) {
            $register(reg)
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_starts_empty() {
        let reg = PluginRegistry::new("test");
        let (tasks, native_tasks, drivers, exporters, source) = reg.drain();
        assert!(tasks.is_empty());
        assert!(native_tasks.is_empty());
        assert!(drivers.is_empty());
        assert!(exporters.is_empty());
        assert_eq!(source, "test");
    }

    #[test]
    fn entry_symbol_is_the_documented_name() {
        // Don't let anyone "fix" the symbol name without bumping ABI_VERSION.
        assert_eq!(ENTRY_SYMBOL, b"secator_plugin_v1_register");
    }
}
