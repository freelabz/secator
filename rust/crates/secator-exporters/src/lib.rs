//! Report exporters (formatters writing files to a report folder).
//!
//! Maps to Python `secator/exporters/`. The MVP set is `json` / `csv` / `txt` — the
//! ones in `CONFIG.tasks.exporters` by default. Markdown / GDrive land later.
//! See `../docs/rewrite/08-subsystems.md` §1.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use secator_model::OutputItem;
use secator_report::Report;

#[derive(Debug)]
pub enum ExportError {
    Io(String),
    Other(String),
}
impl std::fmt::Display for ExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExportError::Io(s) => write!(f, "exporter io: {s}"),
            ExportError::Other(s) => write!(f, "exporter: {s}"),
        }
    }
}
impl std::error::Error for ExportError {}
impl From<std::io::Error> for ExportError {
    fn from(e: std::io::Error) -> Self { ExportError::Io(e.to_string()) }
}

/// One-method formatter over a built report.
pub trait Exporter: Send + Sync {
    /// Format/persist the report. Returns the paths written (for `[INF] Saved ...` lines).
    fn send(&self, report: &Report) -> Result<Vec<PathBuf>, ExportError>;
    /// Short name used in `[INF] Saved <NAME> reports to ...`.
    fn name(&self) -> &'static str;
}

// ---------------------------------------------------------------------- JSON

/// Single `report.json` containing `{info, results: {type: [items...]}}` (Python parity).
///
/// `info` includes start/end timestamps, elapsed human string, run_opts, context, errors.
/// `results` always includes every finding type + `target` with an `[]` placeholder
/// when no items of that type were emitted (Python iterates `FINDING_TYPES + [Target]`).
/// Field order within items follows the model's declaration order — relies on the
/// `preserve_order` feature on `serde_json` (enabled in `secator-model/Cargo.toml`).
pub struct JsonExporter;
impl Exporter for JsonExporter {
    fn name(&self) -> &'static str { "JSON" }
    fn send(&self, report: &Report) -> Result<Vec<PathBuf>, ExportError> {
        let path = report.output_folder.join("report.json");
        let mut results = serde_json::Map::new();
        // Python ordering: subdomain, ip, port, url, tag, exploit, user_account,
        // vulnerability, certificate, record, domain, ai, technology, target.
        for ty in secator_model::FINDING_TYPE_NAMES
            .iter()
            .copied()
            .chain(std::iter::once("target"))
        {
            let arr: Vec<serde_json::Value> = report
                .results
                .get(ty)
                .map(|items| items.iter().map(|i| serde_json::Value::Object(i.to_map())).collect())
                .unwrap_or_default();
            results.insert(ty.to_string(), serde_json::Value::Array(arr));
        }
        let mut top = serde_json::Map::new();
        top.insert("info".into(), info_to_json(&report.info));
        top.insert("results".into(), serde_json::Value::Object(results));
        let f = File::create(&path)?;
        serde_json::to_writer_pretty(f, &serde_json::Value::Object(top))
            .map_err(|e| ExportError::Other(e.to_string()))?;
        Ok(vec![path])
    }
}

fn info_to_json(info: &secator_report::ReportInfo) -> serde_json::Value {
    // Insertion-ordered map (with serde_json's preserve_order feature) so the JSON
    // field order matches Python's `runner_fields` set, which iterates in source
    // declaration order: name, status, targets, start_time, end_time, elapsed,
    // elapsed_human, run_opts, results_count, context, title, errors.
    let mut m = serde_json::Map::new();
    m.insert("name".into(), info.name.clone().into());
    m.insert("task_name".into(), info.task_name.clone().into());
    m.insert("status".into(), info.status.clone().into());
    m.insert(
        "targets".into(),
        serde_json::Value::Array(
            info.targets
                .iter()
                .map(|t| serde_json::Value::String(t.clone()))
                .collect(),
        ),
    );
    m.insert("start_time".into(), info.start_time.into());
    m.insert("end_time".into(), info.end_time.into());
    m.insert("elapsed".into(), info.elapsed_seconds.into());
    m.insert("elapsed_human".into(), info.elapsed_human.clone().into());
    m.insert(
        "run_opts".into(),
        serde_json::Value::Object(
            info.run_opts
                .iter()
                .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                .collect(),
        ),
    );
    m.insert("results_count".into(), info.findings_count.into());
    m.insert("context".into(), serde_json::Value::Object(info.context.clone()));
    m.insert("workspace".into(), info.workspace.clone().into());
    m.insert("title".into(), info.title.clone().into());
    m.insert(
        "errors".into(),
        serde_json::Value::Array(
            info.errors
                .iter()
                .map(|e| serde_json::Value::String(e.clone()))
                .collect(),
        ),
    );
    m.insert("errors_count".into(), info.errors_count.into());
    serde_json::Value::Object(m)
}

// ----------------------------------------------------------------------- CSV

/// One `report_<type>.csv` per finding type. Columns are the union of fields across
/// items of that type (sorted alphabetically — serde_json::Map is BTreeMap-backed).
pub struct CsvExporter;
impl Exporter for CsvExporter {
    fn name(&self) -> &'static str { "CSV" }
    fn send(&self, report: &Report) -> Result<Vec<PathBuf>, ExportError> {
        let mut written = Vec::new();
        for (ty, items) in &report.results {
            if items.is_empty() {
                continue;
            }
            let path = report.output_folder.join(format!("report_{ty}.csv"));
            // Discover columns. Skip the `_uuid`/`_context`/`_related` etc. internal
            // fields to keep CSVs human-readable.
            let mut columns: BTreeSet<String> = BTreeSet::new();
            for item in items {
                for k in item.to_map().keys() {
                    if !k.starts_with('_') {
                        columns.insert(k.clone());
                    }
                }
            }
            let cols: Vec<String> = columns.into_iter().collect();
            let mut w = csv::Writer::from_path(&path).map_err(|e| ExportError::Other(e.to_string()))?;
            w.write_record(&cols).map_err(|e| ExportError::Other(e.to_string()))?;
            for item in items {
                let map = item.to_map();
                let row: Vec<String> = cols
                    .iter()
                    .map(|c| {
                        map.get(c)
                            .map(|v| match v {
                                serde_json::Value::String(s) => s.clone(),
                                other => other.to_string(),
                            })
                            .unwrap_or_default()
                    })
                    .collect();
                w.write_record(&row).map_err(|e| ExportError::Other(e.to_string()))?;
            }
            w.flush()?;
            written.push(path);
        }
        Ok(written)
    }
}

// ------------------------------------------------------------------------ TXT

/// One `report_<type>.txt` per finding type with the primary field (Python `str(item)`)
/// per line. Useful for piping later: `cat report_url.txt | next-tool`.
pub struct TxtExporter;
impl Exporter for TxtExporter {
    fn name(&self) -> &'static str { "TXT" }
    fn send(&self, report: &Report) -> Result<Vec<PathBuf>, ExportError> {
        let mut written = Vec::new();
        for (ty, items) in &report.results {
            if items.is_empty() {
                continue;
            }
            let path = report.output_folder.join(format!("report_{ty}.txt"));
            let mut f = File::create(&path)?;
            for item in items {
                if let Some(line) = primary_field(item) {
                    writeln!(f, "{line}")?;
                }
            }
            written.push(path);
        }
        Ok(written)
    }
}

/// The "primary" field used for raw piping / txt export (Python OutputType `__str__`).
fn primary_field(item: &OutputItem) -> Option<String> {
    match item {
        OutputItem::Url(u) => Some(u.url.clone()),
        OutputItem::Subdomain(s) => Some(s.host.clone()),
        OutputItem::Port(p) => Some(format!("{}:{}", p.host, p.port)),
        OutputItem::Ip(i) => Some(i.ip.clone()),
        OutputItem::Vulnerability(v) => Some(format!("{} -> {}", v.matched_at, v.name)),
        OutputItem::Technology(t) => Some(t.match_.clone()),
        OutputItem::Tag(t) => Some(t.match_.clone()),
        OutputItem::Target(t) => Some(t.name.clone()),
        _ => None,
    }
}

// ----------------------------------------------------------------- Markdown

/// One `report.md` file containing every finding grouped by type with a
/// Markdown table per group. Mirrors Python `MarkdownExporter`.
pub struct MarkdownExporter;
impl Exporter for MarkdownExporter {
    fn name(&self) -> &'static str { "Markdown" }
    fn send(&self, report: &Report) -> Result<Vec<PathBuf>, ExportError> {
        let path = report.output_folder.join("report.md");
        let mut buf = String::new();
        // Header / metadata block.
        buf.push_str(&format!("# {} report\n\n", report.info.task_name));
        buf.push_str("| Field | Value |\n|------|------|\n");
        buf.push_str(&format!("| Workspace | {} |\n", report.info.workspace));
        buf.push_str(&format!("| Status | {} |\n", report.info.status));
        buf.push_str(&format!("| Findings | {} |\n", report.info.findings_count));
        buf.push_str(&format!("| Errors | {} |\n", report.info.errors_count));
        buf.push_str(&format!("| Elapsed (s) | {} |\n", report.info.elapsed_seconds));
        if !report.info.targets.is_empty() {
            buf.push_str(&format!("| Targets | {} |\n", report.info.targets.join(", ")));
        }
        buf.push('\n');
        // Per-type tables. Skip types with no items; honour to_map() ordering.
        for (ty, items) in &report.results {
            if items.is_empty() {
                continue;
            }
            buf.push_str(&format!("## {}s ({})\n\n", capitalize(ty), items.len()));
            let mut columns: BTreeSet<String> = BTreeSet::new();
            for item in items {
                for k in item.to_map().keys() {
                    if !k.starts_with('_') {
                        columns.insert(k.clone());
                    }
                }
            }
            let cols: Vec<String> = columns.into_iter().collect();
            buf.push('|');
            for c in &cols { buf.push_str(&format!(" {c} |")); }
            buf.push('\n');
            buf.push('|');
            for _ in &cols { buf.push_str("------|"); }
            buf.push('\n');
            for item in items {
                let map = item.to_map();
                buf.push('|');
                for c in &cols {
                    let cell = map
                        .get(c)
                        .map(|v| md_escape(&value_to_string(v)))
                        .unwrap_or_default();
                    buf.push_str(&format!(" {cell} |"));
                }
                buf.push('\n');
            }
            buf.push('\n');
        }
        let mut f = File::create(&path)?;
        f.write_all(buf.as_bytes())?;
        Ok(vec![path])
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(first) => first.to_uppercase().collect::<String>() + c.as_str(),
    }
}

fn value_to_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Minimal Markdown escape: collapse newlines to ` / ` (table cells can't wrap)
/// and escape pipes so we don't break the column count.
fn md_escape(s: &str) -> String {
    s.replace('\n', " / ").replace('|', r"\|")
}

// -------------------------------------------------------------- Console table

/// One `report_<type>.table.txt` per finding type — a fixed-width text table
/// suitable for `cat` or pasting into chat. Mirrors Python `TableExporter`.
pub struct TableExporter;
impl Exporter for TableExporter {
    fn name(&self) -> &'static str { "Table" }
    fn send(&self, report: &Report) -> Result<Vec<PathBuf>, ExportError> {
        let mut written = Vec::new();
        for (ty, items) in &report.results {
            if items.is_empty() {
                continue;
            }
            let path = report.output_folder.join(format!("report_{ty}.table.txt"));
            let mut columns: BTreeSet<String> = BTreeSet::new();
            for item in items {
                for k in item.to_map().keys() {
                    if !k.starts_with('_') {
                        columns.insert(k.clone());
                    }
                }
            }
            let cols: Vec<String> = columns.into_iter().collect();
            // Precompute column widths.
            let mut widths: Vec<usize> = cols.iter().map(|c| c.len()).collect();
            let rows: Vec<Vec<String>> = items
                .iter()
                .map(|item| {
                    let map = item.to_map();
                    cols.iter()
                        .map(|c| {
                            let s = map.get(c).map(value_to_string).unwrap_or_default();
                            // Single-line cells only — collapse newlines.
                            s.replace('\n', " ")
                        })
                        .collect()
                })
                .collect();
            for row in &rows {
                for (i, cell) in row.iter().enumerate() {
                    widths[i] = widths[i].max(cell.chars().count());
                }
            }
            let mut buf = String::new();
            // Header.
            for (i, c) in cols.iter().enumerate() {
                buf.push_str(&format!("{:<width$} ", c, width = widths[i]));
            }
            buf.push('\n');
            for w in &widths {
                buf.push_str(&"-".repeat(*w));
                buf.push(' ');
            }
            buf.push('\n');
            for row in rows {
                for (i, cell) in row.iter().enumerate() {
                    buf.push_str(&format!("{:<width$} ", cell, width = widths[i]));
                }
                buf.push('\n');
            }
            std::fs::write(&path, buf)?;
            written.push(path);
        }
        Ok(written)
    }
}

// ----------------------------------------------------------------------- JSONL

/// Newline-delimited JSON — one object per item, written to
/// `report.jsonl` in the output folder. Python parity with
/// `exporters/jsonl.py` (which prints to stdout for `jq` piping); we write to
/// disk so the file lands next to `report.json` and the operator can `cat` /
/// pipe at their convenience. The order matches Python: iterate every finding
/// type in declaration order, then any items that fall into the catch-all
/// `target` bucket.
pub struct JsonlExporter;
impl Exporter for JsonlExporter {
    fn name(&self) -> &'static str { "JSONL" }
    fn send(&self, report: &Report) -> Result<Vec<PathBuf>, ExportError> {
        let path = report.output_folder.join("report.jsonl");
        let mut f = File::create(&path)?;
        for ty in secator_model::FINDING_TYPE_NAMES
            .iter()
            .copied()
            .chain(std::iter::once("target"))
        {
            let Some(items) = report.results.get(ty) else { continue };
            for item in items {
                let map = item.to_map();
                let line = serde_json::to_string(&serde_json::Value::Object(map))
                    .map_err(|e| ExportError::Other(e.to_string()))?;
                writeln!(f, "{line}")?;
            }
        }
        Ok(vec![path])
    }
}

// ---------------------------------------------------------------- Console

/// Stream every finding to stdout, one line per item, formatted via
/// [`primary_field`] (same rendering as `TxtExporter` but on stdout for live
/// piping). Python parity with `exporters/console.py`.
///
/// Returns an empty path list — nothing is written to disk, so the CLI's
/// `[INF] Saved <NAME> reports to ...` line is skipped for this exporter.
pub struct ConsoleExporter;
impl Exporter for ConsoleExporter {
    fn name(&self) -> &'static str { "Console" }
    fn send(&self, report: &Report) -> Result<Vec<PathBuf>, ExportError> {
        use std::io::Write as _;
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        for ty in secator_model::FINDING_TYPE_NAMES
            .iter()
            .copied()
            .chain(std::iter::once("target"))
        {
            let Some(items) = report.results.get(ty) else { continue };
            for item in items {
                if let Some(line) = primary_field(item) {
                    let _ = writeln!(handle, "{line}");
                }
            }
        }
        let _ = handle.flush();
        Ok(Vec::new())
    }
}

// ----------------------------------------------------------- Google Drive

/// Upload the rendered `report.json` (and any sibling `report_*.csv` files
/// already on disk) to a per-workspace folder in Google Drive. Python parity
/// with `exporters/gdrive.py`, simplified:
///   * we upload the existing flat report files rather than re-deriving
///     per-output-type spreadsheets (the operator can use Drive's preview);
///   * authentication uses `gcloud auth print-access-token --account=<sa>`
///     (same pattern as the GCS hook) so the operator's existing
///     service-account activation is reused — no native OAuth flow needed.
///
/// Disabled unless `addons.gdrive.enabled` is `true` and both
/// `credentials_path` + `drive_parent_folder_id` are set.
pub struct GdriveExporter;

impl Exporter for GdriveExporter {
    fn name(&self) -> &'static str {
        "GDrive"
    }

    fn send(&self, report: &Report) -> Result<Vec<PathBuf>, ExportError> {
        let cfg = secator_config::get();
        let g = &cfg.addons.gdrive;
        if !g.enabled {
            return Err(ExportError::Other("gdrive exporter not enabled".into()));
        }
        if g.credentials_path.is_empty() {
            return Err(ExportError::Other(
                "gdrive: missing addons.gdrive.credentials_path".into(),
            ));
        }
        if g.drive_parent_folder_id.is_empty() {
            return Err(ExportError::Other(
                "gdrive: missing addons.gdrive.drive_parent_folder_id".into(),
            ));
        }

        // 1. Mint a bearer token via gcloud. The service account must already
        //    be activated with `gcloud auth activate-service-account`.
        let token = gdrive_access_token(&g.service_account_email)?;

        // 2. Find or create the workspace folder under the parent.
        let ws_name = report.info.workspace.clone();
        let workspace_folder = if ws_name.is_empty() {
            g.drive_parent_folder_id.clone()
        } else {
            gdrive_ensure_folder(&token, &ws_name, &g.drive_parent_folder_id)?
        };

        // 3. Upload report.json + any csv siblings already in output_folder.
        let mut uploaded: Vec<PathBuf> = Vec::new();
        let candidates: Vec<PathBuf> = std::fs::read_dir(&report.output_folder)
            .ok()
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                let fname = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
                fname == "report.json" || fname.starts_with("report_") && p.extension().is_some()
            })
            .collect();
        if candidates.is_empty() {
            return Err(ExportError::Other(
                "gdrive: no report.json or report_*.* files to upload (run with -o json first)"
                    .into(),
            ));
        }
        for path in &candidates {
            let fname = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("file")
                .to_string();
            let body = std::fs::read(path)?;
            let mime = guess_mime(&fname);
            gdrive_upload(&token, &workspace_folder, &fname, &body, mime)?;
            uploaded.push(path.clone());
        }
        Ok(uploaded)
    }
}

/// `gcloud auth print-access-token --account=<email>` — short-lived bearer.
fn gdrive_access_token(account_email: &str) -> Result<String, ExportError> {
    let mut cmd = std::process::Command::new("gcloud");
    cmd.args(["auth", "print-access-token"]);
    if !account_email.is_empty() {
        cmd.arg(format!("--account={account_email}"));
    }
    let out = cmd
        .output()
        .map_err(|e| ExportError::Other(format!("gcloud spawn: {e}")))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(ExportError::Other(format!(
            "gcloud auth print-access-token failed: {stderr}"
        )));
    }
    let token = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if token.is_empty() {
        return Err(ExportError::Other("gcloud returned empty token".into()));
    }
    Ok(token)
}

/// Look up a folder by name under `parent_id`, create it if missing, return
/// its file id.
fn gdrive_ensure_folder(
    token: &str,
    name: &str,
    parent_id: &str,
) -> Result<String, ExportError> {
    // List first.
    let q = format!(
        "'{parent_id}' in parents and mimeType='application/vnd.google-apps.folder' and name='{}' and trashed=false",
        name.replace('\'', "\\'")
    );
    let list_url = format!(
        "https://www.googleapis.com/drive/v3/files?q={}&supportsAllDrives=true&includeItemsFromAllDrives=true",
        urlencode(&q)
    );
    let out = curl_get_json(token, &list_url)?;
    if let Some(files) = out.get("files").and_then(|v| v.as_array()) {
        if let Some(id) = files.first().and_then(|f| f.get("id")).and_then(|v| v.as_str()) {
            return Ok(id.to_string());
        }
    }
    // Create.
    let body = serde_json::json!({
        "name": name,
        "mimeType": "application/vnd.google-apps.folder",
        "parents": [parent_id],
    });
    let create_url = "https://www.googleapis.com/drive/v3/files?supportsAllDrives=true";
    let resp = curl_post_json(token, create_url, &body.to_string())?;
    resp.get("id")
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or_else(|| {
            ExportError::Other(format!("gdrive: create folder response missing id: {resp}"))
        })
}

/// Multipart upload to Drive's `/upload` endpoint (Python `gspread/sheets`
/// path is bypassed — we drop the raw file directly).
fn gdrive_upload(
    token: &str,
    parent_folder_id: &str,
    name: &str,
    body: &[u8],
    mime: &str,
) -> Result<(), ExportError> {
    // Write the multipart body to a temp file so curl can stream it.
    let boundary = "----secator-gdrive";
    let metadata = serde_json::json!({
        "name": name,
        "parents": [parent_folder_id],
    });
    let mut buf: Vec<u8> = Vec::new();
    use std::io::Write as _;
    let _ = writeln!(buf, "--{boundary}");
    let _ = writeln!(buf, "Content-Type: application/json; charset=UTF-8");
    let _ = writeln!(buf);
    let _ = writeln!(buf, "{}", metadata);
    let _ = writeln!(buf, "--{boundary}");
    let _ = writeln!(buf, "Content-Type: {mime}");
    let _ = writeln!(buf);
    buf.extend_from_slice(body);
    let _ = writeln!(buf);
    let _ = writeln!(buf, "--{boundary}--");

    let tmp_path = std::env::temp_dir().join(format!(
        "secator-gdrive-{}-{name}",
        std::process::id()
    ));
    std::fs::write(&tmp_path, &buf)?;

    let url = "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&supportsAllDrives=true";
    let status = std::process::Command::new("curl")
        .args([
            "-sS",
            "-X",
            "POST",
            "-H",
            &format!("Authorization: Bearer {token}"),
            "-H",
            &format!("Content-Type: multipart/related; boundary={boundary}"),
            "--data-binary",
            &format!("@{}", tmp_path.display()),
            url,
        ])
        .status()
        .map_err(|e| ExportError::Other(format!("curl spawn: {e}")))?;
    let _ = std::fs::remove_file(&tmp_path);
    if !status.success() {
        return Err(ExportError::Other(format!(
            "gdrive upload `{name}` failed: curl exit {:?}",
            status.code()
        )));
    }
    Ok(())
}

fn curl_get_json(token: &str, url: &str) -> Result<serde_json::Value, ExportError> {
    let out = std::process::Command::new("curl")
        .args([
            "-sS",
            "-H",
            &format!("Authorization: Bearer {token}"),
            url,
        ])
        .output()
        .map_err(|e| ExportError::Other(format!("curl spawn: {e}")))?;
    if !out.status.success() {
        return Err(ExportError::Other(format!(
            "curl GET {url} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    serde_json::from_slice(&out.stdout)
        .map_err(|e| ExportError::Other(format!("curl GET decode: {e}")))
}

fn curl_post_json(token: &str, url: &str, body: &str) -> Result<serde_json::Value, ExportError> {
    let out = std::process::Command::new("curl")
        .args([
            "-sS",
            "-X",
            "POST",
            "-H",
            &format!("Authorization: Bearer {token}"),
            "-H",
            "Content-Type: application/json",
            "-d",
            body,
            url,
        ])
        .output()
        .map_err(|e| ExportError::Other(format!("curl spawn: {e}")))?;
    if !out.status.success() {
        return Err(ExportError::Other(format!(
            "curl POST {url} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    serde_json::from_slice(&out.stdout)
        .map_err(|e| ExportError::Other(format!("curl POST decode: {e}")))
}

/// Minimal urlencode for query parameters (Drive query strings).
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

fn guess_mime(name: &str) -> &'static str {
    let lower = name.to_lowercase();
    if lower.ends_with(".json") {
        "application/json"
    } else if lower.ends_with(".csv") {
        "text/csv"
    } else if lower.ends_with(".md") {
        "text/markdown"
    } else if lower.ends_with(".txt") {
        "text/plain"
    } else if lower.ends_with(".xml") {
        "application/xml"
    } else if lower.ends_with(".yaml") || lower.ends_with(".yml") {
        "application/yaml"
    } else {
        "application/octet-stream"
    }
}

// ----------------------------------------------------------- Registry / resolve

/// Resolve exporter names (e.g. from `-o json,csv`) to instances.
pub fn resolve(names: &[&str]) -> Vec<Box<dyn Exporter>> {
    names
        .iter()
        .filter_map(|n| match *n {
            "json" => Some(Box::new(JsonExporter) as Box<dyn Exporter>),
            "jsonl" => Some(Box::new(JsonlExporter)),
            "csv" => Some(Box::new(CsvExporter)),
            "txt" => Some(Box::new(TxtExporter)),
            "markdown" | "md" => Some(Box::new(MarkdownExporter)),
            "table" => Some(Box::new(TableExporter)),
            "console" => Some(Box::new(ConsoleExporter)),
            "gdrive" => Some(Box::new(GdriveExporter)),
            _ => None,
        })
        .collect()
}

/// The default exporter set for tasks. Reads `CONFIG.tasks.exporters` so users
/// can opt into Markdown/Table by editing `~/.secator/config.yml` (or via
/// `secator config set tasks.exporters json,markdown`). Falls back to a
/// sensible JSON/CSV/TXT triple when the config field is empty.
pub fn default_task_exporters() -> Vec<Box<dyn Exporter>> {
    exporters_for(&secator_config::get().tasks.exporters)
}

/// Same as [`default_task_exporters`] for the workflow exporter set.
pub fn default_workflow_exporters() -> Vec<Box<dyn Exporter>> {
    exporters_for(&secator_config::get().workflows.exporters)
}

/// Same as [`default_task_exporters`] for the scan exporter set.
pub fn default_scan_exporters() -> Vec<Box<dyn Exporter>> {
    exporters_for(&secator_config::get().scans.exporters)
}

fn exporters_for(names: &[String]) -> Vec<Box<dyn Exporter>> {
    let fallback = ["json".to_string(), "csv".into(), "txt".into()];
    let chosen: &[String] = if names.is_empty() { &fallback } else { names };
    let refs: Vec<&str> = chosen.iter().map(String::as_str).collect();
    resolve(&refs)
}

// ----------------------------------------------------------------------- Tests
#[cfg(test)]
mod tests {
    use super::*;
    use secator_model::{Subdomain, Url};
    use secator_report::{Report, ReportInfo};

    fn sample_report(folder: PathBuf) -> Report {
        let items = vec![
            OutputItem::Url(Url {
                url: "https://example.com".into(),
                status_code: 200,
                title: "Example".into(),
                ..Default::default()
            }),
            OutputItem::Subdomain(Subdomain {
                host: "a.example.com".into(),
                domain: "example.com".into(),
                ..Default::default()
            }),
        ];
        Report::build(
            ReportInfo {
                name: "httpx".into(),
                task_name: "httpx".into(),
                status: "SUCCESS".into(),
                ..Default::default()
            },
            &items,
            folder,
        )
    }

    #[test]
    fn json_exporter_writes_report_json() {
        let dir = std::env::temp_dir().join(format!("sec-exp-json-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let report = sample_report(dir.clone());
        let written = JsonExporter.send(&report).unwrap();
        assert_eq!(written.len(), 1);
        assert!(written[0].ends_with("report.json"));
        let text = std::fs::read_to_string(&written[0]).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["info"]["task_name"], "httpx");
        assert_eq!(parsed["results"]["url"][0]["url"], "https://example.com");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn csv_exporter_writes_one_file_per_type() {
        let dir = std::env::temp_dir().join(format!("sec-exp-csv-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let report = sample_report(dir.clone());
        let written = CsvExporter.send(&report).unwrap();
        assert_eq!(written.len(), 2); // url + subdomain
        let names: Vec<String> = written.iter().filter_map(|p| p.file_name().map(|f| f.to_string_lossy().into_owned())).collect();
        assert!(names.contains(&"report_url.csv".to_string()));
        assert!(names.contains(&"report_subdomain.csv".to_string()));
        // Sanity: csv contains the url.
        let url_csv = std::fs::read_to_string(dir.join("report_url.csv")).unwrap();
        assert!(url_csv.contains("https://example.com"));
        // Internal `_uuid` etc. fields are NOT columns.
        assert!(!url_csv.contains("_uuid"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn txt_exporter_writes_primary_field_per_line() {
        let dir = std::env::temp_dir().join(format!("sec-exp-txt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let report = sample_report(dir.clone());
        let _ = TxtExporter.send(&report).unwrap();
        let url_txt = std::fs::read_to_string(dir.join("report_url.txt")).unwrap();
        assert_eq!(url_txt.trim(), "https://example.com");
        let sub_txt = std::fs::read_to_string(dir.join("report_subdomain.txt")).unwrap();
        assert_eq!(sub_txt.trim(), "a.example.com");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_picks_known_names() {
        let xs = resolve(&["json", "csv", "txt", "md", "markdown", "table", "bogus"]);
        // json, csv, txt, md → md, markdown → md, table = 6 picks (md double-resolved).
        assert_eq!(xs.len(), 6);
    }

    #[test]
    fn markdown_exporter_writes_grouped_tables() {
        let dir = std::env::temp_dir().join(format!("sec-exp-md-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let report = sample_report(dir.clone());
        let written = MarkdownExporter.send(&report).unwrap();
        assert_eq!(written.len(), 1);
        assert!(written[0].ends_with("report.md"));
        let body = std::fs::read_to_string(&written[0]).unwrap();
        assert!(body.starts_with("# httpx report"));
        assert!(body.contains("## Urls (1)"));
        assert!(body.contains("https://example.com"));
        assert!(body.contains("## Subdomains (1)"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn table_exporter_writes_per_type_table_files() {
        let dir = std::env::temp_dir().join(format!("sec-exp-tbl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let report = sample_report(dir.clone());
        let written = TableExporter.send(&report).unwrap();
        assert_eq!(written.len(), 2);
        let url_tbl = std::fs::read_to_string(dir.join("report_url.table.txt")).unwrap();
        assert!(url_tbl.contains("https://example.com"));
        // Header followed by separator row of dashes.
        assert!(url_tbl.lines().nth(1).unwrap().contains("---"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn md_escape_pipes_and_newlines() {
        assert_eq!(md_escape("a|b\nc"), r"a\|b / c");
    }

    /// #176 T7: JSONL exporter writes one JSON object per line in
    /// finding-type declaration order. `jq -c` over the file should round-trip.
    #[test]
    fn jsonl_exporter_writes_one_object_per_line() {
        let dir = std::env::temp_dir().join(format!("sec-exp-jsonl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let report = sample_report(dir.clone());
        let written = JsonlExporter.send(&report).unwrap();
        assert_eq!(written.len(), 1);
        assert!(written[0].ends_with("report.jsonl"));
        let body = std::fs::read_to_string(&written[0]).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2, "expected 2 items, one per line");
        for line in &lines {
            let v: serde_json::Value = serde_json::from_str(line).expect("each line is JSON");
            assert!(v.is_object());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #176 T7: Console exporter returns no paths (it streams to stdout) and
    /// doesn't panic. Validating the stdout content from a unit test is
    /// brittle — what we check is the no-paths contract since the CLI uses
    /// that to skip the "Saved … to" log line.
    #[test]
    fn console_exporter_returns_empty_paths() {
        let dir = std::env::temp_dir().join(format!("sec-exp-cons-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let report = sample_report(dir.clone());
        let written = ConsoleExporter.send(&report).unwrap();
        assert!(written.is_empty(), "console exporter must not write files");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #176 T7: `-o jsonl,console` resolves both as proper trait objects.
    #[test]
    fn resolve_picks_jsonl_and_console() {
        let xs = resolve(&["jsonl", "console"]);
        assert_eq!(xs.len(), 2);
        let names: Vec<&str> = xs.iter().map(|e| e.name()).collect();
        assert!(names.contains(&"JSONL"));
        assert!(names.contains(&"Console"));
    }

    #[test]
    fn resolve_recognizes_gdrive() {
        let out = resolve(&["gdrive"]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name(), "GDrive");
    }

    #[test]
    fn guess_mime_covers_common_report_files() {
        assert_eq!(guess_mime("report.json"), "application/json");
        assert_eq!(guess_mime("report.csv"), "text/csv");
        assert_eq!(guess_mime("report.md"), "text/markdown");
        assert_eq!(guess_mime("report_url.csv"), "text/csv");
        assert_eq!(guess_mime("file.unknown"), "application/octet-stream");
    }

    #[test]
    fn urlencode_escapes_reserved_chars() {
        assert_eq!(urlencode("name='X'"), "name%3D%27X%27");
        assert_eq!(urlencode("a b c"), "a%20b%20c");
        assert_eq!(urlencode("safe-name_v1.0"), "safe-name_v1.0");
    }

    #[test]
    fn gdrive_exporter_rejects_unconfigured_run() {
        // No config = disabled. Should refuse cleanly without panicking.
        let tmp = tempfile::tempdir().unwrap();
        let report = sample_report(tmp.path().to_path_buf());
        let err = GdriveExporter.send(&report).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("not enabled") || msg.contains("missing"), "got: {msg}");
    }
}
