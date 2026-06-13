//! Filesystem-backed query — walks `<reports>/<workspace>/{tasks,workflows,scans}/*/report.json`
//! and applies a MongoDB-style filter in memory. Matches Python `query/json.py`.

use serde_json::Value;
use std::path::PathBuf;

use secator_model::FINDING_TYPE_NAMES;

/// Common interface for query backends (Python `QueryBackend`). Read-only for
/// the local backend; Mongo / API impls add `update` and `count`.
pub trait QueryBackend {
    /// Filter findings by `query` (MongoDB-style dict). Returns matched items.
    fn search(&self, query: &Value, limit: Option<usize>) -> Vec<Value>;

    /// Count matching findings.
    fn count(&self, query: &Value) -> usize;
}

/// Filesystem JSON backend (default; no addon needed).
pub struct JsonBackend {
    reports_dir: PathBuf,
    workspace: String,
}

impl JsonBackend {
    pub fn new(reports_dir: PathBuf, workspace: String) -> Self {
        let workspace = if workspace.is_empty() { "default".into() } else { workspace };
        JsonBackend { reports_dir, workspace }
    }

    fn workspace_dir(&self) -> PathBuf {
        self.reports_dir.join(&self.workspace)
    }

    /// Walk every `report.json` and collect each finding flattened with the
    /// runner id stamped on `_context`.
    fn all_findings(&self) -> Vec<Value> {
        let mut out: Vec<Value> = Vec::new();
        let ws = self.workspace_dir();
        for kind in ["tasks", "workflows", "scans"] {
            let dir = ws.join(kind);
            let Ok(entries) = std::fs::read_dir(&dir) else { continue };
            for entry in entries.flatten() {
                if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    continue;
                }
                let id = entry.file_name().to_string_lossy().into_owned();
                let report = entry.path().join("report.json");
                let Ok(body) = std::fs::read_to_string(&report) else { continue };
                let Ok(json) = serde_json::from_str::<Value>(&body) else { continue };
                let Some(results) = json.get("results").and_then(|v| v.as_object()) else {
                    continue;
                };
                let singular = kind.trim_end_matches('s');
                for ty in FINDING_TYPE_NAMES {
                    let Some(arr) = results.get(*ty).and_then(|v| v.as_array()) else { continue };
                    for item in arr {
                        let mut item = item.clone();
                        stamp_context(&mut item, singular, &id, &self.workspace);
                        out.push(item);
                    }
                }
            }
        }
        out
    }
}

fn stamp_context(item: &mut Value, runner_kind: &str, runner_id: &str, workspace: &str) {
    let obj = match item {
        Value::Object(m) => m,
        _ => return,
    };
    let ctx_entry = obj
        .entry("_context")
        .or_insert(Value::Object(Default::default()));
    if let Value::Object(ctx) = ctx_entry {
        ctx.insert(format!("{runner_kind}_id"), Value::String(runner_id.into()));
        ctx.entry("workspace_id".to_string())
            .or_insert(Value::String(workspace.into()));
    }
}

impl QueryBackend for JsonBackend {
    fn search(&self, query: &Value, limit: Option<usize>) -> Vec<Value> {
        let all = self.all_findings();
        let scanned = all.len();
        let mut matched: Vec<Value> = all
            .into_iter()
            .filter(|item| matches_query(item, query))
            .collect();
        secator_debug::debug!(
            "query.json",
            "ws={} scanned={} matched={} limit={:?}",
            self.workspace, scanned, matched.len(), limit
        );
        if let Some(n) = limit {
            matched.truncate(n);
        }
        matched
    }

    fn count(&self, query: &Value) -> usize {
        self.search(query, None).len()
    }
}

/// Evaluate a MongoDB-style filter against `item`. Supports:
/// * top-level key/value equality
/// * dotted paths (`_context.workspace_id`)
/// * comparison ops (`$eq`, `$ne`, `$gt`, `$gte`, `$lt`, `$lte`, `$regex`, `$in`)
/// * logical ops (`$and`, `$or`)
pub fn matches_query(item: &Value, query: &Value) -> bool {
    let Value::Object(qobj) = query else { return true };
    for (k, v) in qobj {
        match k.as_str() {
            "$and" => {
                let Value::Array(arr) = v else { return false };
                if !arr.iter().all(|sub| matches_query(item, sub)) {
                    return false;
                }
            }
            "$or" => {
                let Value::Array(arr) = v else { return false };
                if !arr.iter().any(|sub| matches_query(item, sub)) {
                    return false;
                }
            }
            _ => {
                let lhs = lookup_path(item, k);
                if !matches_value(lhs.as_ref(), v) {
                    return false;
                }
            }
        }
    }
    true
}

fn matches_value(lhs: Option<&Value>, rhs: &Value) -> bool {
    match rhs {
        Value::Object(m) if m.keys().all(|k| k.starts_with('$')) => {
            for (op, val) in m {
                if !apply_op(lhs, op, val) {
                    return false;
                }
            }
            true
        }
        _ => lhs.map(|l| l == rhs).unwrap_or(false),
    }
}

fn apply_op(lhs: Option<&Value>, op: &str, val: &Value) -> bool {
    match op {
        "$eq" => lhs.map(|l| l == val).unwrap_or(false),
        "$ne" => lhs.map(|l| l != val).unwrap_or(true),
        "$gt" => compare_num(lhs, val, |a, b| a > b),
        "$gte" => compare_num(lhs, val, |a, b| a >= b),
        "$lt" => compare_num(lhs, val, |a, b| a < b),
        "$lte" => compare_num(lhs, val, |a, b| a <= b),
        "$regex" => match (lhs.and_then(|v| v.as_str()), val.as_str()) {
            (Some(s), Some(pat)) => regex::Regex::new(pat).map(|r| r.is_match(s)).unwrap_or(false),
            _ => false,
        },
        "$in" => match (lhs, val.as_array()) {
            (Some(l), Some(arr)) => arr.iter().any(|x| x == l),
            _ => false,
        },
        _ => false,
    }
}

fn compare_num(lhs: Option<&Value>, rhs: &Value, cmp: impl Fn(f64, f64) -> bool) -> bool {
    let a = lhs.and_then(|v| v.as_f64());
    let b = rhs.as_f64();
    match (a, b) {
        (Some(a), Some(b)) => cmp(a, b),
        _ => false,
    }
}

/// Look up a dotted path inside `item`. `_context.scan_id` → item.context.scan_id.
fn lookup_path<'a>(item: &'a Value, path: &str) -> Option<Value> {
    let mut current = item;
    for segment in path.split('.') {
        let Value::Object(obj) = current else { return None };
        let next = obj.get(segment)?;
        current = next;
    }
    Some(current.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn flat_equality_matches() {
        let item = json!({"host": "example.com"});
        assert!(matches_query(&item, &json!({"host": "example.com"})));
        assert!(!matches_query(&item, &json!({"host": "other"})));
    }

    #[test]
    fn dotted_path_resolves() {
        let item = json!({"_context": {"scan_id": "5"}});
        assert!(matches_query(&item, &json!({"_context.scan_id": "5"})));
    }

    #[test]
    fn dollar_gt_compares_numbers() {
        let item = json!({"cvss_score": 8.5});
        assert!(matches_query(&item, &json!({"cvss_score": {"$gt": 7}})));
        assert!(!matches_query(&item, &json!({"cvss_score": {"$gt": 9}})));
    }

    #[test]
    fn dollar_regex_matches_strings() {
        let item = json!({"url": "https://admin.example.com"});
        assert!(matches_query(&item, &json!({"url": {"$regex": "admin"}})));
        assert!(!matches_query(&item, &json!({"url": {"$regex": "missing"}})));
    }

    #[test]
    fn dollar_or_short_circuits() {
        let item = json!({"name": "foo"});
        assert!(matches_query(
            &item,
            &json!({"$or": [{"name": "foo"}, {"name": "bar"}]})
        ));
    }

    #[test]
    fn dollar_and_requires_all() {
        let item = json!({"name": "foo", "x": 1});
        assert!(matches_query(
            &item,
            &json!({"$and": [{"name": "foo"}, {"x": 1}]})
        ));
        assert!(!matches_query(
            &item,
            &json!({"$and": [{"name": "foo"}, {"x": 2}]})
        ));
    }

    #[test]
    fn dollar_in_match_list() {
        let item = json!({"severity": "high"});
        assert!(matches_query(
            &item,
            &json!({"severity": {"$in": ["critical", "high"]}})
        ));
        assert!(!matches_query(
            &item,
            &json!({"severity": {"$in": ["low"]}})
        ));
    }

    #[test]
    fn missing_field_does_not_match_equality() {
        let item = json!({"host": "x"});
        assert!(!matches_query(&item, &json!({"port": 443})));
    }

    #[test]
    fn missing_field_matches_dollar_ne() {
        // Mongo semantics: missing field matches `$ne` (Python parity is not strict
        // here — our default returns true for missing-field $ne, which is the
        // Mongo behaviour. This is the chosen interpretation.)
        let item = json!({"host": "x"});
        assert!(matches_query(&item, &json!({"port": {"$ne": 443}})));
    }
}
