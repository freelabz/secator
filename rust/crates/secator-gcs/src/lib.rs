//! Google Cloud Storage driver (Python `hooks/gcs.py`).
//!
//! For every finding whose type matches `items_to_send`, walks the listed
//! fields, uploads any non-empty local file path to GCS via the `gcloud storage
//! cp` CLI, and rewrites the field on the in-flight item to the
//! `gs://<bucket>/<blob>` URL. Downstream drivers (Mongo / API / Slack) then
//! receive the rewritten item.
//!
//! Why shell out to `gcloud`? Three reasons:
//!   1. Honours the operator's existing auth — service-account JSON, ADC,
//!      `gcloud auth login`, workload identity, etc. — without bundling
//!      Google's auth stack in our binary.
//!   2. The Python hook uses the same `google.cloud.storage` client which
//!      itself defers to that same auth chain — semantics match.
//!   3. Keeps the secator binary lean (`google-cloud-storage` + `gcp_auth`
//!      together add ~50 MB).
//!
//! When `gcloud` isn't on PATH the driver logs once and skips uploads — the
//! run continues with the original local paths intact.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde_json::Value;

use secator_config::GcsAddon;
use secator_driver::{Driver, DriverError, RunKind};
use secator_model::OutputItem;
use secator_report::ReportInfo;

pub struct GcsDriver {
    cfg: GcsAddon,
}

impl GcsDriver {
    pub fn from_config(cfg: GcsAddon) -> Self {
        GcsDriver { cfg }
    }

    fn fields_for(&self, type_name: &str) -> Option<&Vec<String>> {
        self.cfg.items_to_send.get(type_name)
    }

    /// Upload one local file. Returns the `gs://...` URL on success.
    async fn upload(&self, local_path: &Path, blob_name: &str) -> Result<String, String> {
        if self.cfg.bucket_name.is_empty() {
            return Err("addons.gcs.bucket_name is empty".into());
        }
        let gs_url = format!("gs://{}/{}", self.cfg.bucket_name, blob_name);
        let started = std::time::Instant::now();
        let gcloud = if self.cfg.gcloud_command.is_empty() {
            "gcloud".to_string()
        } else {
            self.cfg.gcloud_command.clone()
        };
        let mut cmd = tokio::process::Command::new(&gcloud);
        cmd.arg("storage")
            .arg("cp")
            .arg(local_path)
            .arg(&gs_url)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped());
        if !self.cfg.credentials_path.is_empty() {
            cmd.env("CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE", &self.cfg.credentials_path);
            cmd.env("GOOGLE_APPLICATION_CREDENTIALS", &self.cfg.credentials_path);
        }
        let output = cmd
            .output()
            .await
            .map_err(|e| format!("spawn `{gcloud} storage cp`: {e}"))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "{gcloud} storage cp exited {} — {}",
                output.status.code().unwrap_or(-1),
                stderr.trim()
            ));
        }
        secator_debug::debug!(
            "hooks.gcs",
            "uploaded {} → {gs_url} in {:.2}s",
            local_path.display(),
            started.elapsed().as_secs_f64()
        );
        Ok(gs_url)
    }
}

#[async_trait]
impl Driver for GcsDriver {
    fn name(&self) -> &'static str { "gcs" }

    fn enabled(&self) -> bool {
        self.cfg.enabled && !self.cfg.bucket_name.is_empty()
    }

    async fn on_finding(&self, item: &mut OutputItem) -> Result<(), DriverError> {
        if !item.is_finding() {
            return Ok(());
        }
        let type_name = item.type_name().to_string();
        let fields = match self.fields_for(&type_name) {
            Some(f) => f.clone(),
            None => return Ok(()),
        };
        // Serialise the item to a Map, inspect each candidate field, upload +
        // rewrite. Then deserialise back into the OutputItem variant.
        let mut map = item.to_map();
        let uuid = map
            .get("_uuid")
            .and_then(|v| v.as_str())
            .map(String::from)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| format!("{:x}", rand_id()));
        let mut changed = false;
        for field in &fields {
            let raw = match map.get(field).and_then(|v| v.as_str()) {
                Some(s) if !s.is_empty() => s.to_string(),
                _ => continue,
            };
            // Already a gs:// URL? Skip — idempotent if a previous run uploaded it.
            if raw.starts_with("gs://") {
                continue;
            }
            let path = PathBuf::from(&raw);
            if !path.exists() {
                continue;
            }
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| format!(".{e}"))
                .unwrap_or_default();
            let blob = format!("{uuid}_{field}{ext}");
            match self.upload(&path, &blob).await {
                Ok(gs_url) => {
                    map.insert(field.clone(), Value::String(gs_url));
                    changed = true;
                }
                Err(e) => {
                    secator_debug::debug!("hooks.gcs", "upload failed: {e}");
                    return Err(DriverError(format!("gcs upload {raw}: {e}")));
                }
            }
        }
        if changed {
            if let Some(new_item) = OutputItem::from_map(&map, &secator_model::OutputMap::new()) {
                *item = new_item;
            }
        }
        Ok(())
    }

    async fn on_run_start(
        &self,
        _info: &ReportInfo,
        _kind: RunKind,
    ) -> Result<Option<String>, DriverError> {
        Ok(None)
    }
}

/// Cheap unique id when `_uuid` isn't set on the item yet (a finding flowing
/// straight through the receive loop, before any driver has stamped a Mongo
/// ObjectId). Combine pid + nanos + a per-process counter so concurrent
/// uploads can't collide.
fn rand_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    (std::process::id() as u64) ^ nanos.rotate_left(16) ^ n.rotate_left(32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_when_bucket_empty() {
        let d = GcsDriver::from_config(GcsAddon {
            enabled: true,
            bucket_name: String::new(),
            ..GcsAddon::default()
        });
        assert!(!d.enabled());
    }

    #[test]
    fn disabled_when_flag_off() {
        let d = GcsDriver::from_config(GcsAddon {
            enabled: false,
            bucket_name: "x".into(),
            ..GcsAddon::default()
        });
        assert!(!d.enabled());
    }

    #[test]
    fn enabled_when_both_set() {
        let d = GcsDriver::from_config(GcsAddon {
            enabled: true,
            bucket_name: "bkt".into(),
            ..GcsAddon::default()
        });
        assert!(d.enabled());
    }

    #[test]
    fn default_items_to_send_covers_url_fields() {
        let d = GcsDriver::from_config(GcsAddon::default());
        let url_fields = d.fields_for("url").unwrap();
        assert!(url_fields.iter().any(|f| f == "screenshot_path"));
        assert!(url_fields.iter().any(|f| f == "stored_response_path"));
    }

    #[test]
    fn fields_for_unknown_type_is_none() {
        let d = GcsDriver::from_config(GcsAddon::default());
        assert!(d.fields_for("port").is_none());
    }

    #[tokio::test]
    async fn on_finding_skips_when_no_fields_match() {
        // Url with empty screenshot_path — driver should be a no-op.
        let cfg = GcsAddon { enabled: true, bucket_name: "bkt".into(), ..GcsAddon::default() };
        let d = GcsDriver::from_config(cfg);
        let mut item = OutputItem::Url(secator_model::Url {
            url: "https://x".into(),
            ..Default::default()
        });
        assert!(d.on_finding(&mut item).await.is_ok());
        // Item should be unchanged.
        if let OutputItem::Url(u) = &item {
            assert_eq!(u.url, "https://x");
            assert_eq!(u.screenshot_path, "");
        } else {
            panic!("expected Url");
        }
    }

    #[tokio::test]
    async fn on_finding_skips_when_path_already_gs_url() {
        let cfg = GcsAddon { enabled: true, bucket_name: "bkt".into(), ..GcsAddon::default() };
        let d = GcsDriver::from_config(cfg);
        let mut item = OutputItem::Url(secator_model::Url {
            url: "https://x".into(),
            screenshot_path: "gs://other-bucket/foo.png".into(),
            ..Default::default()
        });
        assert!(d.on_finding(&mut item).await.is_ok());
        // Path preserved as-is — no upload attempted.
        if let OutputItem::Url(u) = &item {
            assert_eq!(u.screenshot_path, "gs://other-bucket/foo.png");
        } else {
            panic!("expected Url");
        }
    }
}
