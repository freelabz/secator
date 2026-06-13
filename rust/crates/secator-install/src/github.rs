//! GitHub-releases installer (Python `GithubInstaller`).
//!
//! Fetches release metadata from the GitHub API, picks the matching asset for the host
//! OS/arch, downloads it, extracts (tar.gz / zip / raw binary), and places the binary
//! under the destination dir. Honors `SECATOR_CLI_GITHUB_TOKEN` to dodge rate limits.

use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use flate2::read::GzDecoder;
use serde_json::Value;
use tar::Archive;
use zip::ZipArchive;

/// Errors returned by `install_from_github` — mirrors Python `InstallerStatus` codes
/// for the GH path so callers can map them onto the public `InstallStatus`.
#[derive(Debug, Clone)]
pub enum GhError {
    /// API call to GitHub failed or returned non-2xx.
    FetchReleaseFailed(String),
    /// `tag_name` not found / version mismatch.
    ReleaseNotFound(String),
    /// No release asset matched (system, arch).
    NoMatchingAsset { system: String, arch: String },
    /// Download of the matched asset failed.
    DownloadFailed(String),
    /// Extracted the archive but couldn't find a binary matching `repo_name`.
    BinaryNotInArchive(String),
    /// Filesystem error during extract / move / chmod.
    FsError(String),
}

impl std::fmt::Display for GhError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GhError::FetchReleaseFailed(e) => write!(f, "release fetch failed: {e}"),
            GhError::ReleaseNotFound(t) => write!(f, "release not found: {t}"),
            GhError::NoMatchingAsset { system, arch } => {
                write!(f, "no matching asset (system={system}, arch={arch})")
            }
            GhError::DownloadFailed(e) => write!(f, "asset download failed: {e}"),
            GhError::BinaryNotInArchive(b) => {
                write!(f, "binary {b:?} not found in extracted archive")
            }
            GhError::FsError(e) => write!(f, "filesystem error: {e}"),
        }
    }
}
impl std::error::Error for GhError {}

/// Options passed to `install_from_github`. `target_binary_name` overrides the
/// default (`repo`) when the operator wants a custom on-disk name (Python
/// `install_binary_name`, e.g. `whois-go` to avoid colliding with system `whois`).
#[derive(Debug, Clone)]
pub struct GhOptions<'a> {
    pub handle: &'a str,
    pub version: &'a str,
    /// Optional version prefix prepended to non-`latest` tags (Python
    /// `install_github_version_prefix`).
    pub version_prefix: &'a str,
    pub target_binary_name: Option<&'a str>,
    pub dest_dir: &'a Path,
    /// Optional bearer token. If `None`, falls back to `SECATOR_CLI_GITHUB_TOKEN`.
    pub token: Option<&'a str>,
    /// HTTP request timeout (Python uses 5s).
    pub timeout: Duration,
    /// Allow callers to inject a stub HTTP client in tests.
    pub http: HttpClient,
}

impl<'a> GhOptions<'a> {
    pub fn new(handle: &'a str, dest_dir: &'a Path) -> Self {
        Self {
            handle,
            version: "latest",
            version_prefix: "",
            target_binary_name: None,
            dest_dir,
            token: None,
            timeout: Duration::from_secs(5),
            http: default_http(),
        }
    }
}

/// HTTP client trait — implementations: real `ureq`-backed and `MockHttp` for tests.
pub type HttpClient = fn(&str, Option<&str>, Duration) -> Result<HttpResponse, String>;

#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

pub fn default_http() -> HttpClient {
    real_http_get
}

fn real_http_get(
    url: &str,
    bearer: Option<&str>,
    timeout: Duration,
) -> Result<HttpResponse, String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(timeout)
        .user_agent("secator-install/0.1")
        .build();
    let mut req = agent.get(url);
    if let Some(tok) = bearer {
        req = req.set("Authorization", &format!("Bearer {tok}"));
    }
    match req.call() {
        Ok(resp) => {
            let status = resp.status();
            let mut body = Vec::new();
            resp.into_reader()
                .read_to_end(&mut body)
                .map_err(|e| format!("read body: {e}"))?;
            Ok(HttpResponse { status, body })
        }
        // ureq returns an error variant for non-2xx — peel out the response so we can
        // surface its status code rather than collapse everything to "transport".
        Err(ureq::Error::Status(code, resp)) => {
            let mut body = Vec::new();
            let _ = resp.into_reader().read_to_end(&mut body);
            Ok(HttpResponse { status: code, body })
        }
        Err(e) => Err(format!("transport: {e}")),
    }
}

/// Full pipeline. Returns the final on-disk binary path on success.
pub fn install_from_github(opts: &GhOptions) -> Result<PathBuf, GhError> {
    let (owner, repo) = split_handle(opts.handle).ok_or_else(|| {
        GhError::FetchReleaseFailed(format!("bad handle: {}", opts.handle))
    })?;
    let release = get_release(opts, &owner, &repo)?;
    let (system, arch, os_ids, arch_ids) = platform_identifiers();
    let asset_url = match find_matching_asset(&release, &os_ids, &arch_ids) {
        Some(url) => url,
        None => return Err(GhError::NoMatchingAsset { system, arch }),
    };
    let bytes = download_asset(opts, &asset_url)?;
    let final_name = opts.target_binary_name.unwrap_or(&repo);
    place_binary(&bytes, &asset_url, &repo, final_name, opts.dest_dir)
}

/// Split `owner/repo` into its parts.
fn split_handle(handle: &str) -> Option<(String, String)> {
    let (a, b) = handle.split_once('/')?;
    if a.is_empty() || b.is_empty() {
        return None;
    }
    Some((a.to_string(), b.to_string()))
}

fn get_release(opts: &GhOptions, owner: &str, repo: &str) -> Result<Value, GhError> {
    let url = if opts.version == "latest" {
        format!("https://api.github.com/repos/{owner}/{repo}/releases/latest")
    } else {
        format!(
            "https://api.github.com/repos/{owner}/{repo}/releases/tags/{}{}",
            opts.version_prefix, opts.version
        )
    };
    let token = opts
        .token
        .map(String::from)
        .or_else(|| std::env::var("SECATOR_CLI_GITHUB_TOKEN").ok());
    let resp = (opts.http)(&url, token.as_deref(), opts.timeout)
        .map_err(GhError::FetchReleaseFailed)?;
    if resp.status == 404 {
        return Err(GhError::ReleaseNotFound(opts.version.into()));
    }
    if !(200..300).contains(&resp.status) {
        return Err(GhError::FetchReleaseFailed(format!(
            "HTTP {status}",
            status = resp.status
        )));
    }
    serde_json::from_slice(&resp.body)
        .map_err(|e| GhError::FetchReleaseFailed(format!("json parse: {e}")))
}

/// `(system, arch, os_ids, arch_ids)` — Python `_get_platform_identifier`.
pub fn platform_identifiers() -> (String, String, Vec<&'static str>, Vec<&'static str>) {
    let system = match std::env::consts::OS {
        "linux" => "linux",
        "macos" => "darwin",
        "windows" => "windows",
        other => other,
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        "x86" => "386",
        "arm" => "armv7l",
        other => other,
    };
    let os_ids: Vec<&'static str> = match system {
        "linux" => vec!["linux"],
        "windows" => vec!["windows", "win"],
        "darwin" => vec!["darwin", "macos", "osx", "mac"],
        _ => vec![],
    };
    let arch_ids: Vec<&'static str> = match arch {
        "x86_64" | "amd64" => vec!["amd64", "x86_64", "64bit", "x64"],
        "aarch64" => vec!["arm64", "aarch64"],
        "armv7l" => vec!["armv7", "arm"],
        "386" => vec!["386", "x86", "i386", "32bit", "x32"],
        _ => vec![],
    };
    (system.into(), arch.into(), os_ids, arch_ids)
}

/// Pick the best asset for the platform (Python `_find_matching_asset`). Returns the
/// `browser_download_url`, preferring `.tar.gz` then `.zip` then anything.
pub fn find_matching_asset(release: &Value, os_ids: &[&str], arch_ids: &[&str]) -> Option<String> {
    let assets = release.get("assets")?.as_array()?;
    let mut matches: Vec<String> = Vec::new();
    for a in assets {
        let name = a
            .get("name")
            .and_then(|v| v.as_str())
            .map(|s| s.to_lowercase())
            .unwrap_or_default();
        let url = a
            .get("browser_download_url")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if url.is_empty() {
            continue;
        }
        let os_ok = os_ids.iter().any(|id| name.contains(id));
        let arch_ok = arch_ids.iter().any(|id| name.contains(id));
        if os_ok && arch_ok {
            matches.push(url);
        }
    }
    for fmt in &[".tar.gz", ".zip"] {
        if let Some(m) = matches.iter().find(|u| u.ends_with(fmt)) {
            return Some(m.clone());
        }
    }
    matches.into_iter().next()
}

fn download_asset(opts: &GhOptions, url: &str) -> Result<Vec<u8>, GhError> {
    // Asset URLs are pre-signed S3 URLs — they reject Bearer headers, so pass `None`.
    let resp = (opts.http)(url, None, opts.timeout.saturating_mul(6))
        .map_err(GhError::DownloadFailed)?;
    if !(200..300).contains(&resp.status) {
        return Err(GhError::DownloadFailed(format!("HTTP {}", resp.status)));
    }
    Ok(resp.body)
}

/// Extract the archive (if any) into a fresh temp dir, find the binary that begins with
/// `repo_name` (Python's matching rule), `chmod 755`, rename to `dest_dir/final_name`.
fn place_binary(
    bytes: &[u8],
    url: &str,
    repo_name: &str,
    final_name: &str,
    dest_dir: &Path,
) -> Result<PathBuf, GhError> {
    std::fs::create_dir_all(dest_dir)
        .map_err(|e| GhError::FsError(format!("mkdir dest: {e}")))?;
    let extract_dir = tmp_dir_for(repo_name)?;
    extract_archive(bytes, url, &extract_dir)?;
    let bin = find_binary(&extract_dir, repo_name)
        .ok_or_else(|| GhError::BinaryNotInArchive(repo_name.into()))?;
    make_executable(&bin)?;
    let dest = dest_dir.join(final_name);
    if dest.exists() {
        let _ = std::fs::remove_file(&dest);
    }
    std::fs::rename(&bin, &dest).or_else(|_| {
        // rename can fail across filesystems — copy+remove fallback.
        std::fs::copy(&bin, &dest)
            .map(|_| ())
            .map_err(|e| GhError::FsError(format!("move binary: {e}")))?;
        let _ = std::fs::remove_file(&bin);
        Ok::<(), GhError>(())
    })?;
    Ok(dest)
}

fn tmp_dir_for(repo: &str) -> Result<PathBuf, GhError> {
    // Include a per-process atomic counter so parallel `install` runs (and parallel
    // unit tests) get distinct extraction dirs.
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let p = std::env::temp_dir().join(format!(
        "{repo}-secator-{}-{n}",
        std::process::id(),
    ));
    if p.exists() {
        let _ = std::fs::remove_dir_all(&p);
    }
    std::fs::create_dir_all(&p)
        .map_err(|e| GhError::FsError(format!("mkdir tmp: {e}")))?;
    Ok(p)
}

/// Decide extractor by URL extension (Python parity).
fn extract_archive(bytes: &[u8], url: &str, dest: &Path) -> Result<(), GhError> {
    let lower = url.to_lowercase();
    if lower.ends_with(".zip") {
        let mut archive = ZipArchive::new(Cursor::new(bytes))
            .map_err(|e| GhError::FsError(format!("open zip: {e}")))?;
        for i in 0..archive.len() {
            let mut entry = archive
                .by_index(i)
                .map_err(|e| GhError::FsError(format!("zip entry: {e}")))?;
            // Resolve a safe path (no `..` escape).
            let outpath = match entry.enclosed_name() {
                Some(p) => dest.join(p),
                None => continue,
            };
            if entry.is_dir() {
                std::fs::create_dir_all(&outpath)
                    .map_err(|e| GhError::FsError(format!("mkdir entry: {e}")))?;
            } else {
                if let Some(parent) = outpath.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| GhError::FsError(format!("mkdir parent: {e}")))?;
                }
                let mut f = std::fs::File::create(&outpath)
                    .map_err(|e| GhError::FsError(format!("create entry: {e}")))?;
                std::io::copy(&mut entry, &mut f)
                    .map_err(|e| GhError::FsError(format!("write entry: {e}")))?;
            }
        }
    } else if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
        let gz = GzDecoder::new(bytes);
        Archive::new(gz)
            .unpack(dest)
            .map_err(|e| GhError::FsError(format!("tar.gz unpack: {e}")))?;
    } else if lower.ends_with(".tar") {
        Archive::new(bytes)
            .unpack(dest)
            .map_err(|e| GhError::FsError(format!("tar unpack: {e}")))?;
    } else {
        // Raw binary (Python `else:` branch).
        let basename = url.rsplit('/').next().unwrap_or("binary");
        let path = dest.join(basename);
        let mut f = std::fs::File::create(&path)
            .map_err(|e| GhError::FsError(format!("create raw: {e}")))?;
        f.write_all(bytes)
            .map_err(|e| GhError::FsError(format!("write raw: {e}")))?;
    }
    Ok(())
}

/// Walk `dir` and return the first file whose name starts with `binary_name`
/// (Python `file.startswith(binary_name)`). Picks an executable file if multiple
/// match — `nuclei` and `nuclei.tar.gz` would both match by prefix, so we prefer
/// the one without an archive extension.
pub fn find_binary(dir: &Path, binary_name: &str) -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    walk(dir, &mut |p| {
        if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
            if name == binary_name
                || name == &format!("{binary_name}.exe")
                || (name.starts_with(binary_name)
                    && !name.ends_with(".tar.gz")
                    && !name.ends_with(".zip")
                    && !name.ends_with(".tgz")
                    && !name.ends_with(".sig")
                    && !name.ends_with(".md")
                    && !name.ends_with(".txt"))
            {
                candidates.push(p.to_path_buf());
            }
        }
    });
    // Prefer exact match, then `<name>.exe`, then prefix matches by shortest name
    // (so `nuclei` beats `nuclei-docs`).
    candidates.sort_by_key(|p| {
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let exact = (name != binary_name) as u8;
        let exe = (name != format!("{binary_name}.exe")) as u8;
        (exact, exe, name.len())
    });
    candidates.into_iter().next()
}

fn walk(dir: &Path, visit: &mut dyn FnMut(&Path)) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, visit);
        } else {
            visit(&path);
        }
    }
}

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<(), GhError> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)
        .map_err(|e| GhError::FsError(format!("stat: {e}")))?
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms)
        .map_err(|e| GhError::FsError(format!("chmod: {e}")))
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> Result<(), GhError> {
    Ok(())
}

// ----------------------------------------------------------------- Tests

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use serde_json::json;

    thread_local! {
        static MOCK_CALLS: RefCell<Vec<(String, Option<String>)>> = RefCell::new(Vec::new());
    }

    /// Test HTTP that just returns a release-shaped JSON for the first call,
    /// then a tiny gz tarball blob for the second.
    fn make_release(asset_name: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "tag_name": "v1.0.0",
            "assets": [
                {
                    "name": asset_name,
                    "browser_download_url": format!("https://example.test/{asset_name}")
                }
            ]
        }))
        .unwrap()
    }

    fn mock_http(url: &str, bearer: Option<&str>, _timeout: Duration) -> Result<HttpResponse, String> {
        MOCK_CALLS.with(|c| c.borrow_mut().push((url.into(), bearer.map(String::from))));
        if url.contains("api.github.com") {
            let body = make_release("foo-linux-amd64.tar.gz");
            return Ok(HttpResponse { status: 200, body });
        }
        // Pretend the asset returns a real .tar.gz containing a binary named `foo`.
        // Use `append_data` so the tar crate computes the header itself.
        use flate2::write::GzEncoder;
        use flate2::Compression;
        let gz = GzEncoder::new(Vec::new(), Compression::default());
        let mut tar = tar::Builder::new(gz);
        let body = b"hello";
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        tar.append_data(&mut header, "foo", body.as_ref()).unwrap();
        let gz = tar.into_inner().unwrap();
        Ok(HttpResponse { status: 200, body: gz.finish().unwrap() })
    }

    #[test]
    fn end_to_end_install_with_mocked_http() {
        MOCK_CALLS.with(|c| c.borrow_mut().clear());
        let tmp = tempfile::tempdir().unwrap();
        let opts = GhOptions {
            handle: "owner/foo",
            version: "v1.0.0",
            version_prefix: "",
            target_binary_name: None,
            dest_dir: tmp.path(),
            token: None,
            timeout: Duration::from_millis(100),
            http: mock_http,
        };
        let bin = install_from_github(&opts).expect("install ok");
        assert!(bin.exists(), "binary should exist at {bin:?}");
        assert_eq!(bin.file_name().unwrap(), "foo");
        // Two HTTP calls: release JSON + asset download.
        let calls = MOCK_CALLS.with(|c| c.borrow().clone());
        assert_eq!(calls.len(), 2);
        assert!(calls[0].0.contains("/releases/tags/v1.0.0"));
    }

    #[test]
    fn latest_uses_latest_endpoint() {
        MOCK_CALLS.with(|c| c.borrow_mut().clear());
        let tmp = tempfile::tempdir().unwrap();
        let opts = GhOptions {
            handle: "owner/foo",
            version: "latest",
            version_prefix: "",
            target_binary_name: None,
            dest_dir: tmp.path(),
            token: None,
            timeout: Duration::from_millis(100),
            http: mock_http,
        };
        let _ = install_from_github(&opts);
        let calls = MOCK_CALLS.with(|c| c.borrow().clone());
        assert!(calls[0].0.ends_with("/releases/latest"));
    }

    #[test]
    fn target_name_overrides_filename() {
        let tmp = tempfile::tempdir().unwrap();
        let opts = GhOptions {
            handle: "owner/foo",
            version: "v1.0.0",
            version_prefix: "",
            target_binary_name: Some("foo-renamed"),
            dest_dir: tmp.path(),
            token: None,
            timeout: Duration::from_millis(100),
            http: mock_http,
        };
        let bin = install_from_github(&opts).expect("install ok");
        assert_eq!(bin.file_name().unwrap(), "foo-renamed");
    }

    #[test]
    fn bearer_token_is_forwarded() {
        MOCK_CALLS.with(|c| c.borrow_mut().clear());
        let tmp = tempfile::tempdir().unwrap();
        let opts = GhOptions {
            handle: "owner/foo",
            version: "latest",
            version_prefix: "",
            target_binary_name: None,
            dest_dir: tmp.path(),
            token: Some("ghp_test"),
            timeout: Duration::from_millis(100),
            http: mock_http,
        };
        let _ = install_from_github(&opts);
        let calls = MOCK_CALLS.with(|c| c.borrow().clone());
        assert_eq!(calls[0].1.as_deref(), Some("ghp_test"));
        // Asset download should NOT include the bearer.
        assert_eq!(calls[1].1, None);
    }

    fn make_404_http(_url: &str, _: Option<&str>, _: Duration) -> Result<HttpResponse, String> {
        Ok(HttpResponse { status: 404, body: vec![] })
    }

    #[test]
    fn missing_release_maps_to_release_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let opts = GhOptions {
            handle: "owner/foo",
            version: "v9.9.9",
            version_prefix: "",
            target_binary_name: None,
            dest_dir: tmp.path(),
            token: None,
            timeout: Duration::from_millis(100),
            http: make_404_http,
        };
        let err = install_from_github(&opts).unwrap_err();
        assert!(matches!(err, GhError::ReleaseNotFound(_)));
    }

    #[test]
    fn asset_matching_picks_tar_gz_over_zip() {
        let release = json!({
            "tag_name": "v1.0.0",
            "assets": [
                {"name": "foo-linux-amd64.zip",
                 "browser_download_url": "https://z/foo.zip"},
                {"name": "foo-linux-amd64.tar.gz",
                 "browser_download_url": "https://z/foo.tar.gz"},
                {"name": "foo-linux-amd64",
                 "browser_download_url": "https://z/foo"},
            ]
        });
        let url = find_matching_asset(&release, &["linux"], &["amd64"]).unwrap();
        assert_eq!(url, "https://z/foo.tar.gz");
    }

    #[test]
    fn asset_matching_returns_none_for_no_match() {
        let release = json!({
            "tag_name": "v1.0.0",
            "assets": [{"name": "foo-windows-arm64.zip", "browser_download_url": "u"}]
        });
        assert_eq!(find_matching_asset(&release, &["linux"], &["amd64"]), None);
    }

    #[test]
    fn find_binary_prefers_exact_match() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("nuclei-docs"), b"x").unwrap();
        std::fs::write(tmp.path().join("nuclei"), b"x").unwrap();
        let found = find_binary(tmp.path(), "nuclei").unwrap();
        assert_eq!(found.file_name().unwrap(), "nuclei");
    }

    #[test]
    fn find_binary_skips_archive_files() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("nuclei.tar.gz"), b"x").unwrap();
        std::fs::write(tmp.path().join("nuclei"), b"x").unwrap();
        let found = find_binary(tmp.path(), "nuclei").unwrap();
        assert_eq!(found.file_name().unwrap(), "nuclei");
    }
}
