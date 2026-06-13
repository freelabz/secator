//! Driver trait — runtime-pluggable sink for items + runner lifecycle events
//! (Python `secator/drivers/`).
//!
//! Where exporters write batched per-format files at the end of a run, drivers run
//! **live** through the lifecycle: `on_run_start`, then `on_finding(item)` for each
//! result the runner yields, then `on_run_end(report)`. MongoDB, API/webhook, Slack
//! and Discord drivers all match this shape.
//!
//! Methods are async via `#[async_trait]` so backends with network I/O (Mongo, HTTP)
//! can stay non-blocking — the CLI's stream loop awaits each driver call in turn.

use async_trait::async_trait;

use secator_model::OutputItem;
use secator_report::ReportInfo;

/// Run kind passed to `on_run_start` so a driver can route into different
/// collections / endpoints based on whether it's a task, workflow, or scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunKind {
    Task,
    Workflow,
    Scan,
}

impl RunKind {
    /// Snake-case label used as a Mongo collection / route segment (Python
    /// `f'{type}s'` → `tasks` / `workflows` / `scans`).
    pub fn plural(self) -> &'static str {
        match self {
            RunKind::Task => "tasks",
            RunKind::Workflow => "workflows",
            RunKind::Scan => "scans",
        }
    }
}

/// Errors returned by drivers — opaque `String` so each impl can wrap its
/// transport-specific error without leaking deps upward.
#[derive(Debug, Clone)]
pub struct DriverError(pub String);
impl std::fmt::Display for DriverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for DriverError {}
impl From<String> for DriverError {
    fn from(s: String) -> Self { DriverError(s) }
}
impl From<&str> for DriverError {
    fn from(s: &str) -> Self { DriverError(s.into()) }
}

/// A driver wraps a writable sink — `MongoDriver`, `ApiDriver`, `SlackDriver`, …
/// Methods are async so HTTP/Mongo backends don't have to block the receive loop.
#[async_trait]
pub trait Driver: Send + Sync {
    /// Stable name used for logging and config matching.
    fn name(&self) -> &'static str;

    /// Cheap enable check — returns false when config disables this driver.
    /// CLI consults this once at startup; disabled drivers are filtered out.
    fn enabled(&self) -> bool { true }

    /// Called once at the start of a run with the run metadata. Drivers can use
    /// the returned `Option<String>` as an external ID (Mongo's ObjectId) to
    /// stash for later `update`s. None ⇒ no ID needed.
    async fn on_run_start(
        &self,
        _info: &ReportInfo,
        _kind: RunKind,
    ) -> Result<Option<String>, DriverError> {
        Ok(None)
    }

    /// Called for every typed item the runner emits (live). The item is `&mut`
    /// so drivers can enrich/rewrite (Python `process_item` parity — GCS
    /// rewrites `screenshot_path` to `gs://...` URLs as it uploads).
    async fn on_finding(&self, _item: &mut OutputItem) -> Result<(), DriverError> {
        Ok(())
    }

    /// Called once after the run finishes with the final ReportInfo + all items.
    /// `external_id` is whatever `on_run_start` returned.
    async fn on_run_end(
        &self,
        _info: &ReportInfo,
        _items: &[OutputItem],
        _kind: RunKind,
        _external_id: Option<&str>,
    ) -> Result<(), DriverError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NopDriver;
    #[async_trait]
    impl Driver for NopDriver {
        fn name(&self) -> &'static str { "nop" }
    }

    #[tokio::test]
    async fn default_impls_return_ok() {
        let d = NopDriver;
        assert!(d.enabled());
        let id = d.on_run_start(&ReportInfo::default(), RunKind::Task).await.unwrap();
        assert!(id.is_none());
    }

    #[test]
    fn run_kind_plural_strings() {
        assert_eq!(RunKind::Task.plural(), "tasks");
        assert_eq!(RunKind::Workflow.plural(), "workflows");
        assert_eq!(RunKind::Scan.plural(), "scans");
    }
}
