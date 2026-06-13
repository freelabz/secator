//! Native (in-process) tasks — Python `PythonRunner` parity.
//!
//! Each module exposes a `pub static SPEC: NativeSpec`. The CLI/exec layer
//! treats native specs identically to `TaskSpec` for input/option handling but
//! routes to `NativeRunner` (no subprocess) for execution.

use secator_runner::NativeSpec;

pub mod ai;
pub mod netdetect;
pub mod prompt;
pub mod urlparser;

/// All built-in native task SPECs.
pub fn all() -> Vec<&'static NativeSpec> {
    vec![
        &ai::SPEC,
        &netdetect::SPEC,
        &prompt::SPEC,
        &urlparser::SPEC,
    ]
}

/// Look a native spec up by name.
pub fn get(name: &str) -> Option<&'static NativeSpec> {
    all().into_iter().find(|s| s.name == name)
}
