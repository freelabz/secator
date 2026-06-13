//! MongoDB driver (Python `hooks/mongodb.py`).
//!
//! Persists runner state (`tasks` / `workflows` / `scans` collections) + findings
//! (`findings` collection) into MongoDB. Also exposes a [`query::MongoQueryBackend`]
//! the CLI's `secator q --driver mongodb` path routes through.
//!
//! Lifecycle:
//! * `on_run_start` inserts a runner doc into `<kind>s` and returns the ObjectId.
//! * `on_finding` inserts each finding into `findings`.
//! * `on_run_end` updates the runner doc with the final status/elapsed/error list.

pub mod query;
pub use query::MongoQueryBackend;

use async_trait::async_trait;
use bson::{doc, oid::ObjectId, Bson, Document};
use mongodb::options::ClientOptions;
use mongodb::{Client, Collection, Database};
use std::sync::OnceLock;
use tokio::sync::OnceCell;

use secator_config::MongodbAddon;
use secator_driver::{Driver, DriverError, RunKind};
use secator_model::OutputItem;
use secator_report::ReportInfo;

/// MongoDB driver. Reads config from [`MongodbAddon`] (URL, max_pool, timeout).
pub struct MongoDriver {
    cfg: MongodbAddon,
    /// Lazily-initialised connection — first DB op opens the client.
    client: OnceCell<Client>,
}

impl MongoDriver {
    /// Construct from an `Addons.mongodb` block.
    pub fn from_config(cfg: MongodbAddon) -> Self {
        MongoDriver { cfg, client: OnceCell::new() }
    }

    async fn db(&self) -> Result<Database, DriverError> {
        let client = self
            .client
            .get_or_try_init(|| async {
                let mut opts = ClientOptions::parse(&self.cfg.url)
                    .await
                    .map_err(|e| DriverError(format!("parse mongo url: {e}")))?;
                opts.max_pool_size = Some(self.cfg.max_pool_size);
                opts.server_selection_timeout = Some(std::time::Duration::from_millis(
                    self.cfg.server_selection_timeout_ms,
                ));
                opts.app_name = Some("secator-rs".into());
                Client::with_options(opts)
                    .map_err(|e| DriverError(format!("mongo client: {e}")))
            })
            .await?
            .clone();
        Ok(client.database("main"))
    }

    async fn runner_collection(&self, kind: RunKind) -> Result<Collection<Document>, DriverError> {
        Ok(self.db().await?.collection::<Document>(kind.plural()))
    }

    async fn findings_collection(&self) -> Result<Collection<Document>, DriverError> {
        Ok(self.db().await?.collection::<Document>("findings"))
    }
}

#[async_trait]
impl Driver for MongoDriver {
    fn name(&self) -> &'static str { "mongodb" }
    fn enabled(&self) -> bool { self.cfg.enabled }

    async fn on_run_start(
        &self,
        info: &ReportInfo,
        kind: RunKind,
    ) -> Result<Option<String>, DriverError> {
        let coll = self.runner_collection(kind).await?;
        let doc = info_to_doc(info);
        let res = coll
            .insert_one(doc)
            .await
            .map_err(|e| DriverError(format!("insert runner: {e}")))?;
        let id = extract_object_id(&res.inserted_id);
        secator_debug::debug!("hooks.mongodb", "on_run_start kind={:?} id={:?}", kind, id);
        Ok(id)
    }

    async fn on_finding(&self, item: &mut OutputItem) -> Result<(), DriverError> {
        // Skip non-findings (execution-only items like Info/Warning/Error) so
        // the `findings` collection stays focused on actual results.
        if !item.is_finding() {
            return Ok(());
        }
        let coll = self.findings_collection().await?;
        let doc = item_to_doc(item);
        let res = coll
            .insert_one(doc)
            .await
            .map_err(|e| DriverError(format!("insert finding: {e}")))?;
        secator_debug::debug!(
            "hooks.mongodb",
            "on_finding type={} id={:?}",
            item.type_name(),
            extract_object_id(&res.inserted_id)
        );
        Ok(())
    }

    async fn on_run_end(
        &self,
        info: &ReportInfo,
        _items: &[OutputItem],
        kind: RunKind,
        external_id: Option<&str>,
    ) -> Result<(), DriverError> {
        let coll = self.runner_collection(kind).await?;
        match external_id.and_then(|s| ObjectId::parse_str(s).ok()) {
            Some(id) => {
                coll.update_one(doc! {"_id": id}, doc! {"$set": info_to_doc(info)})
                    .await
                    .map_err(|e| DriverError(format!("update runner: {e}")))?;
            }
            // No prior insert (on_run_start failed or wasn't called) — fall back
            // to an insert so the run is still represented.
            None => {
                coll.insert_one(info_to_doc(info))
                    .await
                    .map_err(|e| DriverError(format!("insert runner end: {e}")))?;
            }
        }
        // Cross-run dedup pass — Python parity with `tag_duplicates`. Tags
        // findings in this workspace as `_duplicate=true` when an older
        // matching finding exists. Best-effort: any error is logged and
        // swallowed since this is a post-run housekeeping step, not part of
        // the run's reported outcome.
        if let Err(e) = self.tag_duplicates(&info.workspace).await {
            secator_debug::debug!(
                "hooks.mongodb",
                "tag_duplicates failed for ws={}: {e}",
                info.workspace
            );
        }
        Ok(())
    }
}

impl MongoDriver {
    /// Cross-run deduplication — sweep the `findings` collection for items in
    /// `workspace_id`, group by compare-key shape, mark the oldest survivors
    /// as primary and the rest as `_duplicate=true` with `_related` pointing
    /// at the survivor's uuid. Python `hooks/mongodb.py::tag_duplicates`,
    /// minus the field-copy-from-previous-main behavior (operators rely on
    /// the survivor's own fields for now).
    pub async fn tag_duplicates(&self, workspace_id: &str) -> Result<(), DriverError> {
        use futures_util::StreamExt;

        let coll = self.findings_collection().await?;
        let filter = doc! { "_context.workspace_id": workspace_id };
        let mut cursor = coll
            .find(filter)
            .await
            .map_err(|e| DriverError(format!("find findings: {e}")))?;

        // Group findings by their "compare shape" — built from the few
        // fields each output_type's dedup uses (Python `compare_key`). We
        // don't have `OutputType::compare_key` directly accessible from
        // bson::Document, so we approximate with the canonical comparison
        // fields per type. Items without a clear shape are skipped.
        let mut by_key: std::collections::HashMap<String, Vec<(ObjectId, f64, String)>> =
            std::collections::HashMap::new();
        while let Some(doc) = cursor.next().await {
            let Ok(doc) = doc else { continue };
            let Ok(oid) = doc.get_object_id("_id") else { continue };
            let ts = doc.get_f64("_timestamp").unwrap_or(0.0);
            let uuid = doc.get_str("_uuid").unwrap_or("").to_string();
            let Some(key) = compare_key_str(&doc) else { continue };
            by_key.entry(key).or_default().push((oid, ts, uuid));
        }

        let mut updates_dup = 0usize;
        let mut updates_primary = 0usize;
        for (_key, mut group) in by_key {
            if group.len() < 2 {
                continue;
            }
            // Earliest timestamp wins (Python parity: keeps the historical
            // record stable as new runs land).
            group.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
            let primary = group[0].clone();
            let related: Vec<String> = group.iter().skip(1).map(|(_, _, u)| u.clone()).collect();
            // Mark primary not-duplicate + record related uuids.
            let _ = coll
                .update_one(
                    doc! { "_id": &primary.0 },
                    doc! { "$set": {
                        "_duplicate": false,
                        "_related": bson::to_bson(&related).unwrap_or(Bson::Null),
                    }},
                )
                .await;
            updates_primary += 1;
            // Tag the others.
            for (oid, _, _) in group.iter().skip(1) {
                let _ = coll
                    .update_one(
                        doc! { "_id": oid },
                        doc! { "$set": {
                            "_duplicate": true,
                            "_related": vec![&primary.2],
                        }},
                    )
                    .await;
                updates_dup += 1;
            }
        }
        secator_debug::debug!(
            "hooks.mongodb",
            "tag_duplicates ws={workspace_id}: primaries={updates_primary} duplicates={updates_dup}"
        );
        Ok(())
    }
}

/// Build a deterministic string key from the fields each output_type uses
/// for dedup. Mirrors `OutputType::compare_key` per-type but operates on a
/// raw BSON document so we can sweep the collection without round-tripping
/// each row through serde. Returns `None` for documents without a `_type`.
fn compare_key_str(doc: &Document) -> Option<String> {
    let ty = doc.get_str("_type").ok()?;
    let parts: Vec<String> = match ty {
        "url" => vec![doc.get_str("url").unwrap_or("").into()],
        "subdomain" => vec![
            doc.get_str("host").unwrap_or("").into(),
            doc.get_str("domain").unwrap_or("").into(),
        ],
        "ip" => vec![
            doc.get_str("ip").unwrap_or("").into(),
            doc.get_bool("alive").unwrap_or(false).to_string(),
            doc.get_str("protocol").unwrap_or("").into(),
        ],
        "port" => vec![
            doc.get_str("ip").unwrap_or("").into(),
            doc.get_i64("port").unwrap_or(0).to_string(),
            doc.get_str("protocol").unwrap_or("").into(),
        ],
        "tag" => vec![
            doc.get_str("name").unwrap_or("").into(),
            doc.get_str("value").unwrap_or("").into(),
            doc.get_str("match").unwrap_or("").into(),
            doc.get_str("category").unwrap_or("").into(),
        ],
        "vulnerability" => vec![
            doc.get_str("name").unwrap_or("").into(),
            doc.get_str("provider").unwrap_or("").into(),
            doc.get_str("id").unwrap_or("").into(),
            doc.get_str("matched_at").unwrap_or("").into(),
            doc.get_str("severity").unwrap_or("").into(),
        ],
        "exploit" => vec![
            doc.get_str("id").unwrap_or("").into(),
            doc.get_str("provider").unwrap_or("").into(),
            doc.get_str("matched_at").unwrap_or("").into(),
        ],
        "technology" => vec![
            doc.get_str("product").unwrap_or("").into(),
            doc.get_str("match").unwrap_or("").into(),
            doc.get_str("version").unwrap_or("").into(),
        ],
        "certificate" => vec![
            doc.get_str("host").unwrap_or("").into(),
            doc.get_str("fingerprint_sha256").unwrap_or("").into(),
        ],
        "domain" => vec![doc.get_str("host").unwrap_or("").into()],
        "user_account" => vec![
            doc.get_str("username").unwrap_or("").into(),
            doc.get_str("site_name").unwrap_or("").into(),
        ],
        "record" => vec![
            doc.get_str("name").unwrap_or("").into(),
            doc.get_str("type").unwrap_or("").into(),
            doc.get_str("host").unwrap_or("").into(),
        ],
        _ => return None,
    };
    Some(format!("{ty}:{}", parts.join("|")))
}

fn extract_object_id(b: &Bson) -> Option<String> {
    match b {
        Bson::ObjectId(oid) => Some(oid.to_hex()),
        Bson::String(s) => Some(s.clone()),
        _ => None,
    }
}

fn info_to_doc(info: &ReportInfo) -> Document {
    // Map ReportInfo → BSON doc. Field names match Python's `Runner.toDict()`.
    let mut d = doc! {
        "name": &info.name,
        "task_name": &info.task_name,
        "status": &info.status,
        "targets": bson_array(info.targets.iter().map(|t| Bson::String(t.clone()))),
        "workspace": &info.workspace,
        "title": &info.title,
        "findings_count": info.findings_count as i64,
        "errors_count": info.errors_count as i64,
        "start_time": info.start_time,
        "end_time": info.end_time,
        "elapsed": info.elapsed_seconds,
        "elapsed_human": &info.elapsed_human,
    };
    if !info.run_opts.is_empty() {
        let mut opts = Document::new();
        for (k, v) in &info.run_opts {
            opts.insert(k, v);
        }
        d.insert("run_opts", opts);
    }
    if !info.context.is_empty() {
        if let Ok(ctx_bson) = bson::to_bson(&info.context) {
            d.insert("context", ctx_bson);
        }
    }
    if !info.errors.is_empty() {
        d.insert("errors", bson_array(info.errors.iter().map(|e| Bson::String(e.clone()))));
    }
    d
}

fn item_to_doc(item: &OutputItem) -> Document {
    // Round-trip through serde_json → BSON so secator-model's `Serialize` impls
    // (with `#[serde(rename = "match")]` etc.) drive the shape. Same approach
    // Python takes with `pymongo` via `bson.json_util`.
    let m = item.to_map();
    bson::to_document(&m).unwrap_or_else(|_| Document::new())
}

fn bson_array<I: IntoIterator<Item = Bson>>(iter: I) -> Bson {
    Bson::Array(iter.into_iter().collect())
}

/// Silence unused-import warnings for `OnceLock` (kept for future shared state).
const _: fn() = || {
    let _: OnceLock<()> = OnceLock::new();
};

#[cfg(test)]
mod tests {
    use super::*;
    use secator_model::{Subdomain, Url};

    #[test]
    fn driver_respects_enabled_flag() {
        let cfg = MongodbAddon { enabled: false, ..MongodbAddon::default() };
        let d = MongoDriver::from_config(cfg);
        assert!(!d.enabled());
    }

    #[test]
    fn item_to_doc_includes_type_discriminator() {
        let item = OutputItem::Url(Url { url: "https://x".into(), ..Default::default() });
        let doc = item_to_doc(&item);
        assert_eq!(doc.get_str("_type").unwrap(), "url");
        assert_eq!(doc.get_str("url").unwrap(), "https://x");
    }

    #[test]
    fn item_to_doc_subdomain_carries_compare_fields() {
        let item = OutputItem::Subdomain(Subdomain {
            host: "a.example.com".into(),
            domain: "example.com".into(),
            ..Default::default()
        });
        let doc = item_to_doc(&item);
        assert_eq!(doc.get_str("host").unwrap(), "a.example.com");
        assert_eq!(doc.get_str("domain").unwrap(), "example.com");
    }

    #[test]
    fn compare_key_str_groups_same_url_separately_from_different_url() {
        let a = doc! { "_type": "url", "url": "https://x.com/a" };
        let b = doc! { "_type": "url", "url": "https://x.com/a" };
        let c = doc! { "_type": "url", "url": "https://x.com/b" };
        assert_eq!(compare_key_str(&a), compare_key_str(&b));
        assert_ne!(compare_key_str(&a), compare_key_str(&c));
    }

    #[test]
    fn compare_key_str_keys_port_by_ip_port_protocol() {
        let a = doc! {"_type":"port","ip":"1.1.1.1","port":22_i64,"protocol":"tcp"};
        let b = doc! {"_type":"port","ip":"1.1.1.1","port":22_i64,"protocol":"tcp","service_name":"ssh"};
        assert_eq!(compare_key_str(&a), compare_key_str(&b));
    }

    #[test]
    fn compare_key_str_returns_none_for_unknown_type() {
        let d = doc! {"_type":"banana"};
        assert!(compare_key_str(&d).is_none());
    }

    #[test]
    fn info_to_doc_preserves_basic_fields() {
        let info = ReportInfo {
            name: "test".into(),
            status: "SUCCESS".into(),
            findings_count: 3,
            elapsed_seconds: 0.5,
            elapsed_human: "0.5s".into(),
            ..ReportInfo::default()
        };
        let d = info_to_doc(&info);
        assert_eq!(d.get_str("name").unwrap(), "test");
        assert_eq!(d.get_str("status").unwrap(), "SUCCESS");
        assert_eq!(d.get_i64("findings_count").unwrap(), 3);
        assert_eq!(d.get_f64("elapsed").unwrap(), 0.5);
    }
}
