//! HTTP API driver (Python `hooks/api.py`).
//!
//! Pushes runner + finding events to a configurable REST endpoint. Matches the
//! Python wire shape:
//! * `POST <runner_create_endpoint>` with the ReportInfo dict → expects `{id}` back.
//! * `PUT  <runner_update_endpoint>` (with `{runner_id}` substituted) for end-of-run.
//! * `POST <finding_create_endpoint>` for each finding.
//!
//! The driver fails open — backend errors are logged via stderr, never abort
//! the run. Also exposes [`query::ApiQueryBackend`] for `secator q --driver api`.

pub mod query;
pub use query::ApiQueryBackend;

use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::{Client, Method};
use serde_json::Value;
use std::time::Duration;

use secator_config::ApiAddon;
use secator_driver::{Driver, DriverError, RunKind};
use secator_model::OutputItem;
use secator_report::ReportInfo;

/// HTTP API driver.
pub struct ApiDriver {
    cfg: ApiAddon,
    client: Client,
}

impl ApiDriver {
    /// Construct from an `Addons.api` block. Builds the reqwest client once;
    /// reuse is safe across threads.
    pub fn from_config(cfg: ApiAddon) -> Result<Self, DriverError> {
        let timeout = Duration::from_secs(cfg.timeout.max(1));
        let mut builder = Client::builder()
            .timeout(timeout)
            .user_agent("secator-rs/0.1");
        if !cfg.force_ssl {
            builder = builder.danger_accept_invalid_certs(true);
        }
        let client = builder
            .build()
            .map_err(|e| DriverError(format!("reqwest client build: {e}")))?;
        Ok(ApiDriver { cfg, client })
    }

    fn header_map(&self) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if !self.cfg.key.is_empty() {
            if let Ok(v) = HeaderValue::from_str(&format!("{} {}", self.cfg.header_name, self.cfg.key))
            {
                h.insert(AUTHORIZATION, v);
            }
        }
        // Reserve room for future X-* headers; lookup helper for tests.
        let _ = HeaderName::from_static("x-secator-version");
        h
    }

    fn url_for(&self, endpoint: &str) -> String {
        let base = self.cfg.url.trim_end_matches('/');
        let ep = endpoint.trim_start_matches('/');
        format!("{base}/{ep}")
    }

    async fn send(
        &self,
        method: Method,
        endpoint: &str,
        body: Option<Value>,
    ) -> Result<Value, DriverError> {
        let url = self.url_for(endpoint);
        secator_debug::debug!("hooks.api", "{} {}", method.as_str(), url);
        let mut req = self.client.request(method.clone(), &url).headers(self.header_map());
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| DriverError(format!("api request {url}: {e}")))?;
        let status = resp.status();
        secator_debug::debug!("hooks.api", "{} {} → {}", method.as_str(), url, status.as_u16());
        let body = resp
            .text()
            .await
            .map_err(|e| DriverError(format!("api body read: {e}")))?;
        if !status.is_success() {
            return Err(DriverError(format!(
                "api {url} returned {status}: {body}"
            )));
        }
        // Empty body is OK — some endpoints return 204.
        if body.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(&body)
            .map_err(|e| DriverError(format!("api response parse: {e}")))
    }
}

#[async_trait]
impl Driver for ApiDriver {
    fn name(&self) -> &'static str { "api" }
    fn enabled(&self) -> bool { self.cfg.enabled }

    async fn on_run_start(
        &self,
        info: &ReportInfo,
        _kind: RunKind,
    ) -> Result<Option<String>, DriverError> {
        let payload = info_to_json(info);
        let resp = self
            .send(Method::POST, &self.cfg.runner_create_endpoint, Some(payload))
            .await?;
        Ok(extract_id(&resp))
    }

    async fn on_finding(&self, item: &mut OutputItem) -> Result<(), DriverError> {
        if !item.is_finding() {
            return Ok(());
        }
        let payload = Value::Object(item.to_map());
        self.send(Method::POST, &self.cfg.finding_create_endpoint, Some(payload))
            .await?;
        Ok(())
    }

    async fn on_run_end(
        &self,
        info: &ReportInfo,
        _items: &[OutputItem],
        _kind: RunKind,
        external_id: Option<&str>,
    ) -> Result<(), DriverError> {
        let payload = info_to_json(info);
        if let Some(id) = external_id {
            let endpoint = self.cfg.runner_update_endpoint.replace("{runner_id}", id);
            self.send(Method::PUT, &endpoint, Some(payload)).await?;
        } else {
            // No prior insert — best-effort POST so the run is at least represented.
            self.send(Method::POST, &self.cfg.runner_create_endpoint, Some(payload))
                .await?;
        }
        Ok(())
    }
}

fn extract_id(v: &Value) -> Option<String> {
    match v {
        Value::Object(m) => m
            .get("id")
            .and_then(|x| x.as_str().map(String::from).or_else(|| x.as_i64().map(|n| n.to_string()))),
        _ => None,
    }
}

fn info_to_json(info: &ReportInfo) -> Value {
    // Match the shape Python's `runner.toDict()` POSTs.
    serde_json::json!({
        "name": info.name,
        "task_name": info.task_name,
        "status": info.status,
        "targets": info.targets,
        "workspace": info.workspace,
        "title": info.title,
        "findings_count": info.findings_count,
        "errors_count": info.errors_count,
        "start_time": info.start_time,
        "end_time": info.end_time,
        "elapsed": info.elapsed_seconds,
        "elapsed_human": info.elapsed_human,
        "run_opts": info.run_opts,
        "context": info.context,
        "errors": info.errors,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_join_strips_double_slashes() {
        let cfg = ApiAddon { url: "https://x.com/api/".into(), ..ApiAddon::default() };
        let d = ApiDriver::from_config(cfg).unwrap();
        assert_eq!(d.url_for("runners"), "https://x.com/api/runners");
        assert_eq!(d.url_for("/runners"), "https://x.com/api/runners");
    }

    #[test]
    fn disabled_addon_returns_false() {
        let cfg = ApiAddon { enabled: false, ..ApiAddon::default() };
        let d = ApiDriver::from_config(cfg).unwrap();
        assert!(!d.enabled());
    }

    #[test]
    fn header_map_includes_bearer_when_key_set() {
        let cfg = ApiAddon {
            key: "abc123".into(),
            header_name: "Bearer".into(),
            ..ApiAddon::default()
        };
        let d = ApiDriver::from_config(cfg).unwrap();
        let h = d.header_map();
        assert_eq!(h.get(AUTHORIZATION).unwrap(), "Bearer abc123");
    }

    #[test]
    fn header_map_omits_auth_when_key_empty() {
        let cfg = ApiAddon { key: String::new(), ..ApiAddon::default() };
        let d = ApiDriver::from_config(cfg).unwrap();
        assert!(d.header_map().get(AUTHORIZATION).is_none());
    }

    #[test]
    fn extract_id_handles_string_and_int() {
        let s = serde_json::json!({"id": "abc"});
        assert_eq!(extract_id(&s), Some("abc".into()));
        let n = serde_json::json!({"id": 42});
        assert_eq!(extract_id(&n), Some("42".into()));
        let none = serde_json::json!({});
        assert_eq!(extract_id(&none), None);
    }

    #[test]
    fn endpoint_substitution_for_runner_update() {
        let cfg = ApiAddon::default();
        let endpoint = cfg.runner_update_endpoint.replace("{runner_id}", "abc-123");
        assert_eq!(endpoint, "runner/abc-123");
    }
}
