//! `scans/5,tasks/3` style path filters (Python `query/utils.parse_report_paths`).

use serde_json::{json, Value};

/// Parse a comma-separated list of runner paths into a Mongo-style filter:
///
/// * `""`         → `{}`
/// * `"scans/5"`         → `{"_context.scan_id": "5"}`
/// * `"scans/5,tasks/3"` → `{"$or": [{"_context.scan_id": "5"}, {"_context.task_id": "3"}]}`
pub fn parse_report_paths(paths_str: &str) -> Value {
    if paths_str.trim().is_empty() {
        return Value::Object(Default::default());
    }
    let parts: Vec<&str> = paths_str
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    let mut filters: Vec<Value> = Vec::new();
    for part in &parts {
        let Some((runner_type, runner_id)) = part.split_once('/') else { continue };
        let runner_type = runner_type.trim().to_lowercase();
        let singular = runner_type.trim_end_matches('s');
        let runner_id = runner_id.trim().trim_end_matches('/');
        filters.push(json!({ format!("_context.{singular}_id"): runner_id }));
    }
    match filters.len() {
        0 => Value::Object(Default::default()),
        1 => filters.into_iter().next().unwrap(),
        _ => json!({"$or": filters}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_returns_empty_object() {
        assert_eq!(parse_report_paths(""), json!({}));
    }

    #[test]
    fn single_scan_path() {
        let q = parse_report_paths("scans/5");
        assert_eq!(q, json!({"_context.scan_id": "5"}));
    }

    #[test]
    fn mixed_paths_use_or() {
        let q = parse_report_paths("scans/5,tasks/3");
        assert_eq!(
            q,
            json!({"$or": [
                {"_context.scan_id": "5"},
                {"_context.task_id": "3"},
            ]})
        );
    }

    #[test]
    fn whitespace_and_trailing_slashes_tolerated() {
        let q = parse_report_paths("  workflows/42/  ");
        assert_eq!(q, json!({"_context.workflow_id": "42"}));
    }

    #[test]
    fn malformed_parts_dropped() {
        // "abc" has no slash → skipped; "tasks/9" kept.
        let q = parse_report_paths("abc,tasks/9");
        assert_eq!(q, json!({"_context.task_id": "9"}));
    }
}
