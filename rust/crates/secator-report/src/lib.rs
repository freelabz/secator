//! Report aggregation + reports-folder allocation.
//!
//! Maps to Python `secator/report.py`. Each runner invocation gets a fresh folder
//! `<reports>/<workspace>/<type>s/<auto-id>/` containing `.inputs/`, `.outputs/`, and
//! the per-format report files written by `secator-exporters`. See
//! `../docs/rewrite/08-subsystems.md` §9.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use secator_model::OutputItem;

/// Lifecycle/identification metadata about a finished run (Python `data['info']`).
///
/// Field set mirrors Python's `Report.build` filter (`runner_fields` in `report.py`):
/// `name, status, targets, start_time, end_time, elapsed, elapsed_human, run_opts,
/// results_count, context, title, errors`. We add `task_name`, `workspace`,
/// `findings_count`, `errors_count` because the Rust side needs them upstream of
/// the report (they're cheap to compute and would otherwise cost a re-walk).
#[derive(Debug, Clone, Default)]
pub struct ReportInfo {
    pub name: String,
    pub task_name: String,
    pub status: String,
    pub targets: Vec<String>,
    pub workspace: String,
    pub title: String,
    pub findings_count: usize,
    pub errors_count: usize,
    /// Unix timestamp seconds when the run started. `0.0` ⇒ unset.
    pub start_time: f64,
    /// Unix timestamp seconds when the run ended. `0.0` ⇒ unset.
    pub end_time: f64,
    /// `end_time - start_time` (Python `elapsed`).
    pub elapsed_seconds: f64,
    /// Human-readable elapsed (e.g. `"12.4s"`, `"1m 3.2s"`) (Python `elapsed_human`).
    pub elapsed_human: String,
    /// Resolved options the runner ran with (Python `run_opts`).
    pub run_opts: BTreeMap<String, String>,
    /// Free-form per-run context (Python `context`). We keep raw JSON values
    /// so workflow/scan composition can stash arbitrary structures here.
    pub context: serde_json::Map<String, serde_json::Value>,
    /// Error messages collected during the run (Python `runner.errors`).
    pub errors: Vec<String>,
}

/// Render seconds as a human-friendly elapsed string (Python `elapsed_human`).
pub fn format_elapsed(seconds: f64) -> String {
    if seconds < 60.0 {
        return format!("{seconds:.1}s");
    }
    let mins = (seconds / 60.0).floor();
    let rem = seconds - mins * 60.0;
    format!("{mins}m {rem:.1}s")
}

/// A built report ready for exporters. Findings are bucketed by `type_name()` so each
/// exporter can emit `report_<type>.{csv,txt}` per bucket.
#[derive(Debug, Clone, Default)]
pub struct Report {
    pub info: ReportInfo,
    pub results: BTreeMap<String, Vec<OutputItem>>,
    pub output_folder: PathBuf,
}

impl Report {
    /// Aggregate items by type, keeping findings + targets (mirrors Python `data['results']`).
    /// Uses `CONFIG.runners.remove_duplicates` as the dedupe flag. CLI callers should
    /// invoke this; tests with non-default behaviour should call [`Report::build_dedupe`].
    pub fn build(info: ReportInfo, items: &[OutputItem], output_folder: PathBuf) -> Report {
        Report::build_dedupe(
            info,
            items,
            output_folder,
            secator_config::get().runners.remove_duplicates,
        )
    }

    /// Explicit-dedupe variant. When `dedupe` is true, items previously flagged
    /// by `mark_duplicates` (their `meta.duplicate == true`) are dropped from
    /// the final report — Python's `Report.build(dedupe=…)` parameter.
    pub fn build_dedupe(
        info: ReportInfo,
        items: &[OutputItem],
        output_folder: PathBuf,
        dedupe: bool,
    ) -> Report {
        let mut results: BTreeMap<String, Vec<OutputItem>> = BTreeMap::new();
        for item in items {
            // Persist findings and targets (Python `FINDING_TYPES + Target`).
            if item.is_finding() || matches!(item, OutputItem::Target(_)) {
                if dedupe && item.meta().duplicate {
                    continue;
                }
                results
                    .entry(item.type_name().to_string())
                    .or_default()
                    .push(item.clone());
            }
        }
        Report { info, results, output_folder }
    }

    pub fn is_empty(&self) -> bool {
        self.results.values().all(|v| v.is_empty())
    }
}

/// Allocate the next reports folder under `base/<workspace>/<kind>s/<id>/` and create
/// the `.inputs/` and `.outputs/` subdirs (Python `Runner.reports_folder`).
///
/// `id` is the next integer above any existing sibling directory whose name is numeric.
pub fn next_reports_folder(
    base: &Path,
    workspace: &str,
    kind: &str,
) -> std::io::Result<PathBuf> {
    let workspace = if workspace.is_empty() { "default" } else { workspace };
    let parent = base.join(sanitize(workspace)).join(format!("{kind}s"));
    std::fs::create_dir_all(&parent)?;
    let id = next_numeric_id(&parent)?;
    let folder = parent.join(id.to_string());
    std::fs::create_dir_all(folder.join(".inputs"))?;
    std::fs::create_dir_all(folder.join(".outputs"))?;
    Ok(folder)
}

fn next_numeric_id(dir: &Path) -> std::io::Result<u64> {
    let mut max = 0u64;
    let mut any = false;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        if let Some(name) = entry.file_name().to_str() {
            if let Ok(n) = name.parse::<u64>() {
                any = true;
                if n > max {
                    max = n;
                }
            }
        }
    }
    Ok(if any { max + 1 } else { 0 })
}

/// Strip filesystem-unsafe characters from a workspace/path component.
/// Mirrors Python's `utils.sanitize_folder_name` (unix defaults): replaces
/// whitespace, `-`, `/`, and NULs with `_` — keeps `.`, `,`, `+`, etc.
pub fn sanitize_folder_name(name: &str) -> String {
    sanitize(name)
}

/// See `sanitize_folder_name`.
fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c == '/' || c == '\0' || c == '-' || c.is_whitespace() {
                '_'
            } else {
                c
            }
        })
        .collect()
}

// ----------------------------------------------------------------------- Tests
#[cfg(test)]
mod tests {
    use super::*;
    use secator_model::{Subdomain, Url};

    #[test]
    fn next_id_starts_at_zero_then_increments() {
        let tmp = std::env::temp_dir().join(format!("secator-report-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);

        let first = next_reports_folder(&tmp, "ws", "task").unwrap();
        assert!(first.ends_with("ws/tasks/0"));
        assert!(first.join(".inputs").is_dir());
        assert!(first.join(".outputs").is_dir());

        let second = next_reports_folder(&tmp, "ws", "task").unwrap();
        assert!(second.ends_with("ws/tasks/1"));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn build_buckets_items_by_type_and_keeps_targets() {
        let items = vec![
            OutputItem::Url(Url { url: "https://a".into(), ..Default::default() }),
            OutputItem::Url(Url { url: "https://b".into(), ..Default::default() }),
            OutputItem::Subdomain(Subdomain {
                host: "a.example.com".into(),
                domain: "example.com".into(),
                ..Default::default()
            }),
        ];
        let r = Report::build(ReportInfo::default(), &items, PathBuf::from("/tmp/x"));
        assert_eq!(r.results.get("url").map(|v| v.len()), Some(2));
        assert_eq!(r.results.get("subdomain").map(|v| v.len()), Some(1));
    }

    #[test]
    fn workspace_with_unsafe_chars_is_sanitized() {
        let tmp = std::env::temp_dir().join(format!("secator-sanitize-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        // Slash → `_`, but dots are kept (Python parity on unix).
        let f = next_reports_folder(&tmp, "my.ws/v2", "task").unwrap();
        assert!(f.to_string_lossy().contains("my.ws_v2"));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn sanitize_keeps_dots_and_replaces_whitespace_hyphens() {
        assert_eq!(sanitize_folder_name("secator.cloud"), "secator.cloud");
        assert_eq!(sanitize_folder_name("my ws-v2"), "my_ws_v2");
        assert_eq!(sanitize_folder_name("a/b\0c"), "a_b_c");
    }

    /// P3.1: `runners.remove_duplicates` controls whether items whose meta
    /// flag `duplicate=true` get stripped from the final report. The Python
    /// default is false (keep duplicates flagged); CLI passes the config flag
    /// into `build_dedupe`.
    #[test]
    fn build_dedupe_strips_duplicate_when_on_keeps_when_off() {
        let mut dup = Url { url: "https://dup".into(), ..Default::default() };
        dup.meta.duplicate = true;
        let items = vec![
            OutputItem::Url(Url { url: "https://keep".into(), ..Default::default() }),
            OutputItem::Url(dup),
        ];
        // Off (Python default): both items make it into the report; consumer
        // can read `_duplicate` to decide what to display.
        let r_off = Report::build_dedupe(ReportInfo::default(), &items, PathBuf::from("/tmp/x"), false);
        assert_eq!(r_off.results.get("url").map(|v| v.len()), Some(2));
        // On: dup is stripped.
        let r_on = Report::build_dedupe(ReportInfo::default(), &items, PathBuf::from("/tmp/x"), true);
        let urls = r_on.results.get("url").cloned().unwrap_or_default();
        assert_eq!(urls.len(), 1, "duplicate should be stripped");
        match &urls[0] {
            OutputItem::Url(u) => assert_eq!(u.url, "https://keep"),
            other => panic!("expected Url, got {other:?}"),
        }
    }
}
