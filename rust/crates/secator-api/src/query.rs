//! HTTP API query backend — Python `query/api.py`.
//!
//! POSTs a MongoDB-style query to `<api_url>/<finding_search_endpoint>`. The
//! upstream returns either a bare array of findings or `{items: [...]}` /
//! `{results: [...]}`; we tolerate all three shapes (Python parity).

use std::time::Duration;

use reqwest::Client;
use serde_json::Value;
use tokio::runtime::Builder;

use secator_config::ApiAddon;
use secator_query::QueryBackend;

pub struct ApiQueryBackend {
    cfg: ApiAddon,
    workspace: String,
}

impl ApiQueryBackend {
    pub fn new(cfg: ApiAddon, workspace: String) -> Self {
        let workspace = if workspace.is_empty() { "default".into() } else { workspace };
        Self { cfg, workspace }
    }

    fn block_on<F, T>(&self, f: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => tokio::task::block_in_place(|| handle.block_on(f)),
            Err(_) => Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio rt build")
                .block_on(f),
        }
    }

    fn client(&self) -> reqwest::Result<Client> {
        Client::builder()
            .timeout(Duration::from_secs(self.cfg.timeout))
            .danger_accept_invalid_certs(!self.cfg.force_ssl)
            .user_agent("secator-rs/0.1")
            .build()
    }

    fn merge_workspace(&self, query: &Value) -> Value {
        // The API treats `_context.workspace_id` as the canonical workspace
        // discriminator (Python parity with QueryBackend.get_base_query).
        let mut base = serde_json::Map::new();
        base.insert(
            "_context.workspace_id".into(),
            Value::String(self.workspace.clone()),
        );
        if let Value::Object(user) = query {
            for (k, v) in user {
                base.insert(k.clone(), v.clone());
            }
        }
        Value::Object(base)
    }

    async fn post(&self, endpoint: &str, body: &Value) -> Option<Value> {
        let client = match self.client() {
            Ok(c) => c,
            Err(e) => {
                secator_debug::debug!("query.api", "client build failed: {e}");
                return None;
            }
        };
        let url = format!(
            "{}/{}",
            self.cfg.url.trim_end_matches('/'),
            endpoint.trim_start_matches('/')
        );
        let mut req = client.post(&url).json(body);
        if !self.cfg.key.is_empty() {
            let auth = format!("{} {}", self.cfg.header_name, self.cfg.key);
            req = req.header("Authorization", auth);
        }
        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                secator_debug::debug!("query.api", "POST {url} send error: {e}");
                return None;
            }
        };
        if !resp.status().is_success() {
            secator_debug::debug!(
                "query.api",
                "POST {url} returned {}",
                resp.status().as_u16()
            );
            return None;
        }
        match resp.json::<Value>().await {
            Ok(v) => Some(v),
            Err(e) => {
                secator_debug::debug!("query.api", "POST {url} decode error: {e}");
                None
            }
        }
    }

    fn extract_items(body: Value) -> Vec<Value> {
        // The upstream returns either a bare array or an object wrapping the
        // results under `items` / `results` (Python parity).
        match body {
            Value::Array(a) => a,
            Value::Object(mut o) => {
                if let Some(Value::Array(a)) = o.remove("items") {
                    return a;
                }
                if let Some(Value::Array(a)) = o.remove("results") {
                    return a;
                }
                Vec::new()
            }
            _ => Vec::new(),
        }
    }
}

impl QueryBackend for ApiQueryBackend {
    fn search(&self, query: &Value, limit: Option<usize>) -> Vec<Value> {
        let body = self.merge_workspace(query);
        let endpoint = format!(
            "{}?skip=0&limit={}",
            self.cfg.finding_search_endpoint,
            limit.unwrap_or(100)
        );
        self.block_on(async move {
            let Some(resp) = self.post(&endpoint, &body).await else {
                return Vec::new();
            };
            let items = Self::extract_items(resp);
            secator_debug::debug!(
                "query.api",
                "ws={} matched={} limit={:?}",
                self.workspace,
                items.len(),
                limit
            );
            items
        })
    }

    fn count(&self, query: &Value) -> usize {
        let body = self.merge_workspace(query);
        let endpoint = format!("{}?skip=0&limit=0", self.cfg.finding_search_endpoint);
        self.block_on(async move {
            let Some(resp) = self.post(&endpoint, &body).await else { return 0 };
            // Upstream count payload: `{ "total": N }`.
            resp.get("total").and_then(|v| v.as_u64()).map(|n| n as usize).unwrap_or(0)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::{matchers::method, Mock, MockServer, ResponseTemplate};

    fn cfg(base_url: String) -> ApiAddon {
        ApiAddon {
            enabled: true,
            url: base_url,
            key: "test-token".into(),
            header_name: "Bearer".into(),
            force_ssl: false,
            timeout: 5,
            finding_search_endpoint: "findings/search".into(),
            ..ApiAddon::default()
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn search_accepts_bare_array_response() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {"_type": "vulnerability", "name": "x"},
                {"_type": "url", "url": "https://x"}
            ])))
            .mount(&server)
            .await;
        let backend = ApiQueryBackend::new(cfg(server.uri()), "demo".into());
        let items = backend.search(&json!({}), Some(10));
        assert_eq!(items.len(), 2);
        assert_eq!(items[0]["_type"], "vulnerability");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn search_accepts_items_wrapper() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "total": 1,
                "items": [{"_type": "url", "url": "https://x"}]
            })))
            .mount(&server)
            .await;
        let backend = ApiQueryBackend::new(cfg(server.uri()), "demo".into());
        let items = backend.search(&json!({}), Some(10));
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["url"], "https://x");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn search_accepts_results_wrapper() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{"_type": "tag"}]
            })))
            .mount(&server)
            .await;
        let backend = ApiQueryBackend::new(cfg(server.uri()), "demo".into());
        let items = backend.search(&json!({}), None);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["_type"], "tag");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn count_reads_total_field() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"total": 42})))
            .mount(&server)
            .await;
        let backend = ApiQueryBackend::new(cfg(server.uri()), "demo".into());
        assert_eq!(backend.count(&json!({})), 42);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn http_error_yields_empty_results() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let backend = ApiQueryBackend::new(cfg(server.uri()), "demo".into());
        assert!(backend.search(&json!({}), Some(5)).is_empty());
        assert_eq!(backend.count(&json!({})), 0);
    }

    #[test]
    fn merge_workspace_overlays_user_query() {
        let backend = ApiQueryBackend::new(cfg("http://x".into()), "ws1".into());
        let merged = backend.merge_workspace(&json!({"_type": "vulnerability"}));
        assert_eq!(merged["_context.workspace_id"], "ws1");
        assert_eq!(merged["_type"], "vulnerability");
    }
}
