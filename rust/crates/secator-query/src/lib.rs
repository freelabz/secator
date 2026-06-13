//! Query layer (Python `secator/query/`).
//!
//! Walks the reports tree (`JsonBackend`) and filters findings with a
//! MongoDB-style query, supporting:
//! * type-only filter: `vulnerability` → `{_type: vulnerability}`
//! * field comparisons: `vulnerability.severity_score > 7`
//! * logical ops: `host == "x" && severity == "high"`, `tag.name == "a" || tag.name == "b"`
//! * raw JSON: `{ "_type": "vulnerability", "severity": "critical" }`
//! * runner-path filter: `scans/5,tasks/3` → `{_context.scan_id: 5}`/`$or: [...]`
//!
//! MongoDB + API backends will be added once the JSON backend is solid; they
//! reuse the same `QueryBackend` trait surface (Python parity).

pub mod expr;
pub mod json_backend;
pub mod paths;

pub use expr::{python_expr_to_mongo, ExprError};
pub use json_backend::{JsonBackend, QueryBackend};
pub use paths::parse_report_paths;
