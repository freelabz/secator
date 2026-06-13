//! `python_expr_to_mongo` (Python `query/utils.py`).
//!
//! Translates a Python-like CLI query expression into a MongoDB-style filter
//! dict. Supports type-only, single-field comparisons, AND/OR combinations,
//! and raw-JSON pass-through.

use serde_json::{json, Map, Value};

#[derive(Debug, Clone)]
pub enum ExprError {
    /// Caller mixed `&&` and `||` in the same expression (Python rejects this).
    MixedLogicalOps,
}

impl std::fmt::Display for ExprError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExprError::MixedLogicalOps => {
                write!(f, "cannot mix && and || in the same query expression")
            }
        }
    }
}
impl std::error::Error for ExprError {}

/// Translate a Python-like CLI query string to a MongoDB-style filter.
pub fn python_expr_to_mongo(query: &str) -> Result<Value, ExprError> {
    let q = query.trim();
    if q.is_empty() {
        return Ok(Value::Object(Map::new()));
    }
    // Raw JSON shortcut.
    if q.starts_with('{') {
        if let Ok(v) = serde_json::from_str::<Value>(q) {
            return Ok(v);
        }
    }
    let normalized = normalize_logical_ops(q);
    let or_parts = split_logical_op(&normalized, "||");
    let and_parts = split_logical_op(&normalized, "&&");

    if or_parts.len() > 1 && and_parts.len() > 1 {
        return Err(ExprError::MixedLogicalOps);
    }
    if or_parts.len() > 1 {
        let arms: Vec<Value> = or_parts.iter().map(|p| parse_single_expr(p)).collect();
        return Ok(json!({"$or": arms}));
    }
    if and_parts.len() > 1 {
        let mut merged = Map::new();
        for part in &and_parts {
            if let Value::Object(m) = parse_single_expr(part) {
                for (k, v) in m {
                    merged.insert(k, v);
                }
            }
        }
        return Ok(Value::Object(merged));
    }
    Ok(parse_single_expr(&normalized))
}

/// Replace Python-style ` and `/` or ` with `&&`/`||`, skipping quoted regions.
fn normalize_logical_ops(query: &str) -> String {
    let bytes = query.as_bytes();
    let mut out = String::with_capacity(query.len());
    let mut in_quote: Option<u8> = None;
    let mut i = 0;
    while i < bytes.len() {
        let ch = bytes[i];
        match in_quote {
            None if ch == b'"' || ch == b'\'' => {
                in_quote = Some(ch);
                out.push(ch as char);
                i += 1;
            }
            Some(q) if ch == q => {
                in_quote = None;
                out.push(ch as char);
                i += 1;
            }
            None => {
                if i + 5 <= bytes.len() && &bytes[i..i + 5] == b" and " {
                    out.push_str(" && ");
                    i += 5;
                } else if i + 4 <= bytes.len() && &bytes[i..i + 4] == b" or " {
                    out.push_str(" || ");
                    i += 4;
                } else {
                    out.push(ch as char);
                    i += 1;
                }
            }
            Some(_) => {
                out.push(ch as char);
                i += 1;
            }
        }
    }
    out
}

/// Split on `op` outside of quoted regions (Python `_split_logical_op`).
fn split_logical_op(query: &str, op: &str) -> Vec<String> {
    let bytes = query.as_bytes();
    let op_bytes = op.as_bytes();
    let mut parts: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut in_quote: Option<u8> = None;
    let mut i = 0;
    while i < bytes.len() {
        let ch = bytes[i];
        match in_quote {
            None if ch == b'"' || ch == b'\'' => {
                in_quote = Some(ch);
                current.push(ch as char);
                i += 1;
            }
            Some(q) if ch == q => {
                in_quote = None;
                current.push(ch as char);
                i += 1;
            }
            None if i + op_bytes.len() <= bytes.len() && &bytes[i..i + op_bytes.len()] == op_bytes => {
                parts.push(current.trim().to_string());
                current.clear();
                i += op_bytes.len();
            }
            _ => {
                current.push(ch as char);
                i += 1;
            }
        }
    }
    parts.push(current.trim().to_string());
    parts.retain(|s| !s.is_empty());
    parts
}

/// Parse a single comparison expression like `vulnerability.severity_score > 7`.
fn parse_single_expr(expr: &str) -> Value {
    let expr = expr.trim();
    if expr.starts_with('{') {
        if let Ok(v) = serde_json::from_str::<Value>(expr) {
            return v;
        }
    }
    // Type-only: matches `^[a-z_]+$`.
    if !expr.is_empty()
        && expr.chars().all(|c| c.is_ascii_lowercase() || c == '_')
    {
        return json!({"_type": expr});
    }
    if let Some((left, op_str, right)) = find_op(expr) {
        let parts: Vec<&str> = left.splitn(2, '.').collect();
        let _type = parts[0].trim();
        let field = parts.get(1).map(|s| s.trim());
        let value = parse_value(right);
        let mut result = Map::new();
        result.insert("_type".into(), Value::String(_type.into()));
        if let Some(f) = field {
            if !f.is_empty() {
                let v = match op_to_mongo(op_str) {
                    None => value,
                    Some(mongo) => json!({ mongo: value }),
                };
                result.insert(f.into(), v);
            }
        }
        return Value::Object(result);
    }
    // Fallback: treat as type name (split on first `.`).
    let parts: Vec<&str> = expr.splitn(2, '.').collect();
    json!({"_type": parts[0].trim()})
}

/// Find the FIRST comparison operator outside quotes. Returns (left, op, right).
/// Operators are ordered longest-first so `>=` matches before `>`.
fn find_op(expr: &str) -> Option<(&str, &str, &str)> {
    const OPS: &[&str] = &[">=", "<=", "!=", "~=", "==", ">", "<"];
    let bytes = expr.as_bytes();
    let mut in_quote: Option<u8> = None;
    let mut i = 0;
    while i < bytes.len() {
        let ch = bytes[i];
        match in_quote {
            None if ch == b'"' || ch == b'\'' => {
                in_quote = Some(ch);
                i += 1;
            }
            Some(q) if ch == q => {
                in_quote = None;
                i += 1;
            }
            None => {
                for op in OPS {
                    let ob = op.as_bytes();
                    if i + ob.len() <= bytes.len() && &bytes[i..i + ob.len()] == ob {
                        // Got it. Split.
                        return Some((&expr[..i], op, &expr[i + ob.len()..]));
                    }
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    None
}

fn op_to_mongo(op: &str) -> Option<&'static str> {
    match op {
        ">=" => Some("$gte"),
        "<=" => Some("$lte"),
        ">" => Some("$gt"),
        "<" => Some("$lt"),
        "!=" => Some("$ne"),
        "~=" => Some("$regex"),
        "==" => None,
        _ => None,
    }
}

fn parse_value(raw: &str) -> Value {
    let trimmed = raw.trim();
    // Quoted strings stay as strings regardless of content.
    if (trimmed.starts_with('\'') && trimmed.ends_with('\''))
        || (trimmed.starts_with('"') && trimmed.ends_with('"'))
    {
        return Value::String(trimmed[1..trimmed.len() - 1].into());
    }
    match trimmed {
        "true" => return Value::Bool(true),
        "false" => return Value::Bool(false),
        "null" | "None" => return Value::Null,
        _ => {}
    }
    if let Ok(n) = trimmed.parse::<i64>() {
        return Value::Number(n.into());
    }
    if let Ok(n) = trimmed.parse::<f64>() {
        if let Some(num) = serde_json::Number::from_f64(n) {
            return Value::Number(num);
        }
    }
    Value::String(trimmed.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_query_is_empty_object() {
        let q = python_expr_to_mongo("").unwrap();
        assert_eq!(q, json!({}));
    }

    #[test]
    fn json_passthrough() {
        let q = python_expr_to_mongo(r#"{"_type": "url", "host": "x"}"#).unwrap();
        assert_eq!(q, json!({"_type": "url", "host": "x"}));
    }

    #[test]
    fn type_only_expression() {
        let q = python_expr_to_mongo("vulnerability").unwrap();
        assert_eq!(q, json!({"_type": "vulnerability"}));
    }

    #[test]
    fn single_comparison_gt() {
        let q = python_expr_to_mongo("vulnerability.cvss_score > 7").unwrap();
        assert_eq!(q, json!({"_type": "vulnerability", "cvss_score": {"$gt": 7}}));
    }

    #[test]
    fn single_comparison_eq_strips_quotes() {
        let q = python_expr_to_mongo("url.host == 'example.com'").unwrap();
        assert_eq!(q, json!({"_type": "url", "host": "example.com"}));
    }

    #[test]
    fn regex_comparison() {
        let q = python_expr_to_mongo("url.url ~= 'admin'").unwrap();
        assert_eq!(q, json!({"_type": "url", "url": {"$regex": "admin"}}));
    }

    #[test]
    fn and_with_double_amp() {
        let q = python_expr_to_mongo("url.host == 'x' && url.status_code == 200").unwrap();
        assert_eq!(
            q,
            json!({"_type": "url", "host": "x", "status_code": 200})
        );
    }

    #[test]
    fn and_with_python_keyword() {
        let q = python_expr_to_mongo("url.host == 'x' and url.status_code == 200").unwrap();
        assert_eq!(
            q,
            json!({"_type": "url", "host": "x", "status_code": 200})
        );
    }

    #[test]
    fn or_builds_dollar_or() {
        let q = python_expr_to_mongo("tag.name == 'a' || tag.name == 'b'").unwrap();
        assert_eq!(
            q,
            json!({"$or": [
                {"_type": "tag", "name": "a"},
                {"_type": "tag", "name": "b"},
            ]})
        );
    }

    #[test]
    fn mixed_and_or_rejected() {
        let err = python_expr_to_mongo("a == 1 && b == 2 || c == 3");
        assert!(matches!(err, Err(ExprError::MixedLogicalOps)));
    }

    #[test]
    fn quoted_string_with_op_inside_not_split() {
        let q = python_expr_to_mongo("url.host == 'x > y'").unwrap();
        assert_eq!(q, json!({"_type": "url", "host": "x > y"}));
    }

    #[test]
    fn float_value_kept_as_float() {
        let q = python_expr_to_mongo("vulnerability.cvss_score >= 7.5").unwrap();
        // 7.5 → JSON Number
        assert_eq!(
            q,
            json!({"_type": "vulnerability", "cvss_score": {"$gte": 7.5}})
        );
    }
}
