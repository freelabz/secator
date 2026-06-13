//! MongoDB-backed query layer — Python `query/mongodb.py`.
//!
//! Implements [`secator_query::QueryBackend`] against the `findings` collection
//! used by the Mongo driver. Search runs the same MongoDB filter document the
//! JSON backend produces — `python_expr_to_mongo` is the shared source of truth
//! so `secator q --driver mongodb 'vulnerability.severity == "critical"'`
//! returns the same shape as the JSON backend on a freshly-rendered report.

use std::time::Duration;

use bson::{doc, Bson, Document};
use futures_util::TryStreamExt;
use mongodb::options::{ClientOptions, FindOptions};
use mongodb::{Client, Collection};
use serde_json::Value;
use tokio::runtime::Builder;

use secator_config::MongodbAddon;
use secator_query::QueryBackend;

pub struct MongoQueryBackend {
    cfg: MongodbAddon,
    workspace: String,
}

impl MongoQueryBackend {
    pub fn new(cfg: MongodbAddon, workspace: String) -> Self {
        let workspace = if workspace.is_empty() { "default".into() } else { workspace };
        Self { cfg, workspace }
    }

    /// Run `f` on a one-shot tokio runtime so the sync `QueryBackend` trait can
    /// drive the async MongoDB client. We spawn a private current-thread
    /// runtime per call — the CLI's outer runtime stays untouched.
    fn block_on<F, T>(&self, f: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        // If we're already inside a tokio runtime, use block_in_place to avoid
        // the "Cannot start a runtime from within a runtime" panic. Otherwise
        // build a fresh one. `try_current` is the cheap check.
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => tokio::task::block_in_place(|| handle.block_on(f)),
            Err(_) => {
                let rt = Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("tokio rt build");
                rt.block_on(f)
            }
        }
    }

    async fn collection(&self) -> Option<Collection<Document>> {
        let mut opts = ClientOptions::parse(&self.cfg.url).await.ok()?;
        opts.max_pool_size = Some(self.cfg.max_pool_size);
        opts.server_selection_timeout =
            Some(Duration::from_millis(self.cfg.server_selection_timeout_ms));
        opts.app_name = Some("secator-rs-query".into());
        let client = Client::with_options(opts).ok()?;
        Some(client.database("main").collection::<Document>("findings"))
    }

    /// Workspace filter — Python `QueryBackend.get_base_query` stamps
    /// `_context.workspace_id` on every finding written via the driver.
    fn base_filter(&self) -> Document {
        doc! { "_context.workspace_id": &self.workspace }
    }

    /// Merge the user filter with the workspace filter. Falls back to the
    /// base filter alone when the user query is an empty object.
    fn build_filter(&self, query: &Value) -> Document {
        let user: Document = match value_to_doc(query) {
            Some(d) => d,
            None => return self.base_filter(),
        };
        if user.is_empty() {
            return self.base_filter();
        }
        let mut merged = self.base_filter();
        for (k, v) in user.iter() {
            merged.insert(k, v.clone());
        }
        merged
    }
}

fn value_to_doc(v: &Value) -> Option<Document> {
    match bson::to_bson(v).ok()? {
        Bson::Document(d) => Some(d),
        _ => None,
    }
}

impl QueryBackend for MongoQueryBackend {
    fn search(&self, query: &Value, limit: Option<usize>) -> Vec<Value> {
        let filter = self.build_filter(query);
        self.block_on(async move {
            let Some(coll) = self.collection().await else {
                secator_debug::debug!("query.mongodb", "no collection (config error?)");
                return Vec::new();
            };
            let mut opts = FindOptions::default();
            if let Some(n) = limit {
                opts.limit = Some(n as i64);
            }
            let mut cursor = match coll.find(filter).with_options(opts).await {
                Ok(c) => c,
                Err(e) => {
                    secator_debug::debug!("query.mongodb", "find error: {e}");
                    return Vec::new();
                }
            };
            let mut out: Vec<Value> = Vec::new();
            loop {
                match cursor.try_next().await {
                    Ok(Some(mut doc)) => {
                        // Drop Mongo's internal `_id` — it isn't part of the
                        // finding shape and clashes with future `_id` fields.
                        doc.remove("_id");
                        // BSON → serde_json::Value via the two-step conversion
                        // (bson preserves type tags that serde_json would lose).
                        let as_bson = match bson::to_bson(&doc) {
                            Ok(b) => b,
                            Err(_) => continue,
                        };
                        if let Ok(v) = serde_json::to_value(as_bson) {
                            out.push(v);
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        secator_debug::debug!("query.mongodb", "cursor error: {e}");
                        break;
                    }
                }
            }
            secator_debug::debug!(
                "query.mongodb",
                "ws={} matched={} limit={:?}",
                self.workspace,
                out.len(),
                limit
            );
            out
        })
    }

    fn count(&self, query: &Value) -> usize {
        let filter = self.build_filter(query);
        self.block_on(async move {
            let Some(coll) = self.collection().await else { return 0 };
            match coll.count_documents(filter).await {
                Ok(n) => n as usize,
                Err(e) => {
                    secator_debug::debug!("query.mongodb", "count error: {e}");
                    0
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> MongodbAddon {
        MongodbAddon { url: "mongodb://127.0.0.1:1/main".into(), ..MongodbAddon::default() }
    }

    #[test]
    fn build_filter_includes_workspace() {
        let b = MongoQueryBackend::new(cfg(), "demo".into());
        let f = b.build_filter(&Value::Object(Default::default()));
        assert_eq!(f.get_str("_context.workspace_id").unwrap(), "demo");
    }

    #[test]
    fn build_filter_merges_user_query() {
        let b = MongoQueryBackend::new(cfg(), "ws1".into());
        let q = serde_json::json!({ "_type": "vulnerability", "severity": "high" });
        let f = b.build_filter(&q);
        assert_eq!(f.get_str("_context.workspace_id").unwrap(), "ws1");
        assert_eq!(f.get_str("_type").unwrap(), "vulnerability");
        assert_eq!(f.get_str("severity").unwrap(), "high");
    }

    #[test]
    fn empty_query_falls_back_to_base_only() {
        let b = MongoQueryBackend::new(cfg(), "ws".into());
        let f = b.build_filter(&serde_json::json!({}));
        assert_eq!(f.len(), 1);
        assert!(f.contains_key("_context.workspace_id"));
    }

    #[test]
    fn defaults_workspace_when_empty_string() {
        let b = MongoQueryBackend::new(cfg(), String::new());
        let f = b.build_filter(&serde_json::json!({}));
        assert_eq!(f.get_str("_context.workspace_id").unwrap(), "default");
    }

    #[test]
    fn search_returns_empty_when_connection_fails() {
        // 127.0.0.1:1 isn't a Mongo server — the connection times out, search
        // logs the error and yields an empty vec rather than panicking.
        let b = MongoQueryBackend::new(cfg(), "demo".into());
        let results = b.search(&serde_json::json!({}), Some(5));
        assert!(results.is_empty());
    }
}
