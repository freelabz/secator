//! `custom_templates:` — third-party template packs, each a git repo declared
//! in `~/.secator/config.yml` that may ship any mix of Rust task plugins,
//! workflow YAMLs, and scan YAMLs.
//!
//! Lifecycle:
//! - `secator template add <url>`   — append to config, then sync just that entry
//! - `secator template sync`        — clone/pull each enabled entry, rebuild
//!                                    task crates whose git ref moved, expose
//!                                    workflow/scan YAMLs via the templates
//!                                    registry
//! - `secator template remove <url>` — drop from config; optionally `--purge`
//!                                     to also delete the clone + built plugins
//!
//! Layout on disk:
//! ```text
//! ~/.secator/
//!   custom/
//!     github.com-user-recon-pack/         # clone (deterministic slug)
//!       .git/                             # regular working copy
//!       Cargo.toml                        # optional (repo has task crates)
//!       secator.yml                       # optional repo manifest
//!       workflows/*.yml                   # optional
//!       scans/*.yml                       # optional
//!       .secator-built-ref                # last rev built successfully
//!       target/release/lib*.so            # cdylibs — loaded at CLI startup
//! ```
//!
//! Design notes:
//! - Shells out to `git` and `cargo`. Both are already required to build the
//!   project so no new external dep.
//! - Skip-if-unchanged: the file `.secator-built-ref` stores the git rev the
//!   dylibs were built from. On the next sync we compare against `git rev-parse
//!   HEAD` and skip the (expensive) rebuild if they match AND at least one
//!   dylib actually exists.
//! - No auto-sync at CLI startup: `sync` is always an explicit command.
//! - The repo manifest (`secator.yml`) is entirely optional; when absent we
//!   fall back to filesystem heuristics (presence of `Cargo.toml`,
//!   `workflows/*.yml`, `scans/*.yml`).

use std::path::{Path, PathBuf};
use std::process::Command;

use secator_config::{custom_templates_dir, user_config_path, Config, CustomTemplate};
use serde::Deserialize;

// ============================================================ Repo-level manifest

/// Optional `secator.yml` shipped inside a template repo. Every field is
/// optional so a repo can decorate itself minimally (a workflow-only pack
/// might set only `workflows`).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct RepoManifest {
    pub name: String,
    pub description: String,
    /// Paths (relative to repo root) whose `Cargo.toml` should be built as a
    /// task plugin. When empty, sync falls back to a single build against the
    /// repo root if a `Cargo.toml` exists there.
    pub tasks: Vec<String>,
    /// Glob patterns (relative to repo root) matching workflow YAML files
    /// exposed at runtime. Fallback: `workflows/*.yml`.
    pub workflows: Vec<String>,
    /// Same for scans. Fallback: `scans/*.yml`.
    pub scans: Vec<String>,
}

impl RepoManifest {
    /// Read `<repo>/secator.yml` if present; return `RepoManifest::default()`
    /// on absent or unreadable manifest so downstream code doesn't have to
    /// distinguish "no file" from "empty file".
    pub fn load(repo: &Path) -> RepoManifest {
        let path = repo.join("secator.yml");
        if !path.is_file() {
            return RepoManifest::default();
        }
        match std::fs::read_to_string(&path) {
            Ok(body) => serde_yaml::from_str(&body).unwrap_or_else(|e| {
                eprintln!(
                    "[WRN] {}: unreadable — {e} (falling back to filesystem heuristics)",
                    path.display()
                );
                RepoManifest::default()
            }),
            Err(e) => {
                eprintln!("[WRN] {}: {e}", path.display());
                RepoManifest::default()
            }
        }
    }

    /// Effective task crate paths (relative to repo root). Falls back to `["."]`
    /// when the manifest is silent AND `<repo>/Cargo.toml` exists.
    pub fn effective_tasks(&self, repo: &Path) -> Vec<PathBuf> {
        if !self.tasks.is_empty() {
            return self.tasks.iter().map(PathBuf::from).collect();
        }
        if repo.join("Cargo.toml").is_file() {
            vec![PathBuf::from(".")]
        } else {
            Vec::new()
        }
    }

    /// Glob patterns for workflow YAMLs. Falls back to `["workflows/*.yml"]`
    /// when the manifest is silent AND the `workflows/` dir exists.
    pub fn effective_workflows(&self, repo: &Path) -> Vec<String> {
        if !self.workflows.is_empty() {
            return self.workflows.clone();
        }
        if repo.join("workflows").is_dir() {
            vec!["workflows/*.yml".into(), "workflows/*.yaml".into()]
        } else {
            Vec::new()
        }
    }

    /// Same for scans. Fallback: `scans/*.yml`.
    pub fn effective_scans(&self, repo: &Path) -> Vec<String> {
        if !self.scans.is_empty() {
            return self.scans.clone();
        }
        if repo.join("scans").is_dir() {
            vec!["scans/*.yml".into(), "scans/*.yaml".into()]
        } else {
            Vec::new()
        }
    }
}

// ========================================================================== Sync

/// Outcome of syncing one custom-template entry — used both for pretty
/// printing (`template sync`) and by callers that need to know whether a
/// rebuild happened.
#[derive(Debug, Clone)]
pub struct SyncResult {
    pub url: String,
    pub status: SyncStatus,
    pub built_dylibs: Vec<PathBuf>,
    pub workflows_registered: Vec<PathBuf>,
    pub scans_registered: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
pub enum SyncStatus {
    Cloned { rev: String },
    Updated { from: String, to: String },
    UnchangedSkippedBuild,
    Disabled,
    Failed(String),
}

/// Run `git clone` or `git fetch && reset --hard`, then rebuild task crates if
/// the git rev has moved (or no build artifact exists yet). Yaml files are
/// left in place — the templates registry walks them at CLI startup.
pub fn sync_one(t: &CustomTemplate) -> SyncResult {
    let slug = t.slug();
    let mut res = SyncResult {
        url: t.url.clone(),
        status: SyncStatus::Failed("uninitialized".into()),
        built_dylibs: Vec::new(),
        workflows_registered: Vec::new(),
        scans_registered: Vec::new(),
    };
    if t.url.trim().is_empty() {
        res.status = SyncStatus::Failed("empty url".into());
        return res;
    }
    if !t.enabled {
        res.status = SyncStatus::Disabled;
        return res;
    }
    let dir = custom_templates_dir().join(&slug);
    if let Err(e) = std::fs::create_dir_all(dir.parent().unwrap_or(&dir)) {
        res.status = SyncStatus::Failed(format!("mkdir custom dir: {e}"));
        return res;
    }

    let branch = t.effective_branch();
    let prev_rev = if dir.join(".git").exists() {
        git_rev_parse(&dir, "HEAD").ok()
    } else {
        None
    };

    match ensure_up_to_date(&dir, &t.url, branch) {
        Ok(()) => {}
        Err(e) => {
            res.status = SyncStatus::Failed(e);
            return res;
        }
    }

    let head = match git_rev_parse(&dir, "HEAD") {
        Ok(r) => r,
        Err(e) => {
            res.status = SyncStatus::Failed(format!("rev-parse HEAD: {e}"));
            return res;
        }
    };

    // Skip rebuild when the previously-built rev matches HEAD AND at least
    // one dylib is on disk (protects against a stale ref file left after a
    // manual `rm -rf target`).
    let manifest = RepoManifest::load(&dir);
    let task_paths = manifest.effective_tasks(&dir);
    let should_build = if task_paths.is_empty() {
        false
    } else {
        !built_ref_matches(&dir, &head) || !has_any_dylib(&dir)
    };

    if should_build {
        for rel in &task_paths {
            let crate_dir = dir.join(rel);
            let manifest_path = crate_dir.join("Cargo.toml");
            if !manifest_path.is_file() {
                res.status = SyncStatus::Failed(format!(
                    "task path {} has no Cargo.toml",
                    rel.display()
                ));
                return res;
            }
            eprintln!("[INF] [{slug}] cargo build --release ({})", rel.display());
            let status = Command::new("cargo")
                .arg("build")
                .arg("--release")
                .arg("--manifest-path")
                .arg(&manifest_path)
                .status();
            match status {
                Ok(s) if s.success() => {}
                Ok(s) => {
                    res.status = SyncStatus::Failed(format!("cargo build exited {s}"));
                    return res;
                }
                Err(e) => {
                    res.status = SyncStatus::Failed(format!("spawn cargo: {e}"));
                    return res;
                }
            }
        }
        write_built_ref(&dir, &head);
    }

    // Collect dylibs (whether we built or not — used for the summary).
    res.built_dylibs = collect_dylibs(&dir);
    res.workflows_registered = collect_glob_matches(&dir, &manifest.effective_workflows(&dir));
    res.scans_registered = collect_glob_matches(&dir, &manifest.effective_scans(&dir));

    res.status = match (prev_rev, should_build) {
        (None, _) => SyncStatus::Cloned { rev: head.clone() },
        (Some(prev), true) if prev != head => SyncStatus::Updated { from: prev, to: head },
        _ => SyncStatus::UnchangedSkippedBuild,
    };
    res
}

/// Sync every enabled entry. Disabled entries emit a `SyncStatus::Disabled`
/// row so `template sync` output still lists them.
pub fn sync_all(cfg: &Config) -> Vec<SyncResult> {
    cfg.custom_templates.iter().map(sync_one).collect()
}

/// Append a new URL to `~/.secator/config.yml`. No-op (with warning) if the
/// URL already exists. Returns the (possibly updated) template so the caller
/// can pass it to [`sync_one`].
pub fn add_to_config(url: &str, branch: Option<&str>) -> Result<CustomTemplate, String> {
    let mut cfg = load_user_config()?;
    if let Some(existing) = cfg.custom_templates.iter().find(|t| t.url == url) {
        return Err(format!("`{url}` is already registered (branch = {})", existing.effective_branch()));
    }
    let entry = CustomTemplate {
        url: url.to_string(),
        branch: branch.unwrap_or("").to_string(),
        enabled: true,
        description: String::new(),
    };
    cfg.custom_templates.push(entry.clone());
    save_user_config(&cfg)?;
    Ok(entry)
}

/// Remove a URL from `~/.secator/config.yml`. When `purge = true`, also
/// remove the on-disk clone at `~/.secator/custom/<slug>/`.
pub fn remove_from_config(url: &str, purge: bool) -> Result<(), String> {
    let mut cfg = load_user_config()?;
    let before = cfg.custom_templates.len();
    let removed_slug = cfg
        .custom_templates
        .iter()
        .find(|t| t.url == url)
        .map(|t| t.slug());
    cfg.custom_templates.retain(|t| t.url != url);
    if cfg.custom_templates.len() == before {
        return Err(format!("no custom_templates entry with url `{url}`"));
    }
    save_user_config(&cfg)?;
    if purge {
        if let Some(slug) = removed_slug {
            let clone = custom_templates_dir().join(&slug);
            if clone.exists() {
                std::fs::remove_dir_all(&clone).map_err(|e| {
                    format!("rm -rf {}: {e}", clone.display())
                })?;
                eprintln!("[INF] Purged {}", clone.display());
            }
        }
    }
    Ok(())
}

// ============================================================== Runtime discovery

/// Directories the templates registry should scan for workflow / scan YAMLs.
/// One entry per enabled repo (guaranteed to exist on disk). The registry
/// walks each recursively looking for `*.yml` and `*.yaml`.
pub fn discovery_dirs(cfg: &Config) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for t in &cfg.custom_templates {
        if !t.enabled {
            continue;
        }
        let dir = custom_templates_dir().join(t.slug());
        if dir.is_dir() {
            out.push(dir);
        }
    }
    out
}

// ------------------------------------------------------------------ Git helpers

/// Ensure `<dir>` is a checkout of `<url>@<branch>` at the branch tip. Clones
/// on first run; fetches + hard-resets otherwise.
fn ensure_up_to_date(dir: &Path, url: &str, branch: &str) -> Result<(), String> {
    if dir.join(".git").is_dir() {
        eprintln!("[INF] [{slug}] git fetch origin {branch}", slug = dir.file_name().and_then(|s| s.to_str()).unwrap_or(""));
        run_git(&[
            "-C",
            dir.to_str().ok_or("non-utf8 path")?,
            "fetch",
            "--depth",
            "1",
            "origin",
            branch,
        ])?;
        run_git(&[
            "-C",
            dir.to_str().ok_or("non-utf8 path")?,
            "checkout",
            "-B",
            branch,
        ])?;
        run_git(&[
            "-C",
            dir.to_str().ok_or("non-utf8 path")?,
            "reset",
            "--hard",
            &format!("origin/{branch}"),
        ])?;
    } else {
        eprintln!("[INF] git clone {url} → {}", dir.display());
        run_git(&[
            "clone",
            "--depth",
            "1",
            "--branch",
            branch,
            url,
            dir.to_str().ok_or("non-utf8 path")?,
        ])?;
    }
    Ok(())
}

fn run_git(args: &[&str]) -> Result<(), String> {
    let status = Command::new("git").args(args).status().map_err(|e| {
        format!("spawn `git {}` — {e} (is git installed?)", args.join(" "))
    })?;
    if !status.success() {
        return Err(format!("`git {}` exited {status}", args.join(" ")));
    }
    Ok(())
}

fn git_rev_parse(dir: &Path, refname: &str) -> Result<String, String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .arg("rev-parse")
        .arg(refname)
        .output()
        .map_err(|e| format!("spawn git rev-parse: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

// ------------------------------------------------------------------ Built-ref helpers

fn built_ref_path(dir: &Path) -> PathBuf {
    dir.join(".secator-built-ref")
}

fn built_ref_matches(dir: &Path, rev: &str) -> bool {
    match std::fs::read_to_string(built_ref_path(dir)) {
        Ok(s) => s.trim() == rev,
        Err(_) => false,
    }
}

fn write_built_ref(dir: &Path, rev: &str) {
    if let Err(e) = std::fs::write(built_ref_path(dir), rev) {
        eprintln!("[WRN] could not write .secator-built-ref: {e}");
    }
}

fn has_any_dylib(dir: &Path) -> bool {
    let release = dir.join("target").join("release");
    if !release.is_dir() {
        return false;
    }
    std::fs::read_dir(&release)
        .into_iter()
        .flatten()
        .flatten()
        .any(|e| {
            let p = e.path();
            let ext = p
                .extension()
                .and_then(|e| e.to_str())
                .map(str::to_ascii_lowercase);
            matches!(ext.as_deref(), Some("so" | "dylib" | "dll"))
        })
}

fn collect_dylibs(dir: &Path) -> Vec<PathBuf> {
    let release = dir.join("target").join("release");
    let mut out: Vec<PathBuf> = std::fs::read_dir(&release)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            let ext = p
                .extension()
                .and_then(|e| e.to_str())
                .map(str::to_ascii_lowercase);
            matches!(ext.as_deref(), Some("so" | "dylib" | "dll"))
        })
        .collect();
    out.sort();
    out
}

// ------------------------------------------------------------------ Glob helpers

/// Zero-dep glob matcher: only `*` inside a single path segment is supported
/// (no `**`). Enough for `workflows/*.yml` — anything fancier lands in the
/// manifest's explicit path list.
fn collect_glob_matches(root: &Path, patterns: &[String]) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for pat in patterns {
        // Split on the last '/' — everything before is a directory literal,
        // everything after is the (possibly-wildcarded) filename.
        let (parent, file_pat) = match pat.rsplit_once('/') {
            Some((p, f)) => (root.join(p), f.to_string()),
            None => (root.to_path_buf(), pat.clone()),
        };
        if !parent.is_dir() {
            continue;
        }
        if let Ok(entries) = std::fs::read_dir(&parent) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if simple_glob_match(&file_pat, &name) {
                    out.push(entry.path());
                }
            }
        }
    }
    out.sort();
    out
}

fn simple_glob_match(pattern: &str, s: &str) -> bool {
    // Split by '*' — every literal segment must appear in-order in `s`,
    // anchored at both ends.
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == s;
    }
    let mut cursor = 0usize;
    let first = parts[0];
    if !s[cursor..].starts_with(first) {
        return false;
    }
    cursor += first.len();
    for mid in &parts[1..parts.len() - 1] {
        if mid.is_empty() {
            continue;
        }
        match s[cursor..].find(mid) {
            Some(i) => cursor += i + mid.len(),
            None => return false,
        }
    }
    let last = parts[parts.len() - 1];
    s[cursor..].ends_with(last) && s.len() >= cursor
}

// ------------------------------------------------------------ Config read/write

fn load_user_config() -> Result<Config, String> {
    let path = user_config_path();
    if !path.exists() {
        return Ok(Config::default());
    }
    let text = std::fs::read_to_string(&path).map_err(|e| format!("read config.yml: {e}"))?;
    serde_yaml::from_str(&text).map_err(|e| format!("parse config.yml: {e}"))
}

fn save_user_config(cfg: &Config) -> Result<(), String> {
    let path = user_config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    let body = serde_yaml::to_string(cfg).map_err(|e| format!("serialize config.yml: {e}"))?;
    std::fs::write(&path, body).map_err(|e| format!("write config.yml: {e}"))?;
    Ok(())
}

// ============================================================================== Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_glob_matches_literals_and_wildcards() {
        assert!(simple_glob_match("*.yml", "foo.yml"));
        assert!(simple_glob_match("*.yml", "a.b.yml"));
        assert!(!simple_glob_match("*.yml", "foo.yaml"));
        assert!(simple_glob_match("scan_*.yml", "scan_full.yml"));
        assert!(!simple_glob_match("scan_*.yml", "run_full.yml"));
        assert!(simple_glob_match("plain.yml", "plain.yml"));
        assert!(!simple_glob_match("plain.yml", "other.yml"));
        assert!(simple_glob_match("*", "anything"));
    }

    #[test]
    fn collect_glob_matches_finds_files_under_globbed_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let wf = tmp.path().join("workflows");
        std::fs::create_dir_all(&wf).unwrap();
        std::fs::write(wf.join("a.yml"), "").unwrap();
        std::fs::write(wf.join("b.yaml"), "").unwrap();
        std::fs::write(wf.join("c.txt"), "").unwrap();

        let hits =
            collect_glob_matches(tmp.path(), &["workflows/*.yml".into(), "workflows/*.yaml".into()]);
        assert_eq!(hits.len(), 2);
        assert!(hits.iter().any(|p| p.ends_with("a.yml")));
        assert!(hits.iter().any(|p| p.ends_with("b.yaml")));
    }

    #[test]
    fn repo_manifest_falls_back_to_filesystem() {
        // No secator.yml and no Cargo.toml — tasks list is empty.
        let tmp = tempfile::tempdir().unwrap();
        let m = RepoManifest::load(tmp.path());
        assert!(m.effective_tasks(tmp.path()).is_empty());
        assert!(m.effective_workflows(tmp.path()).is_empty());

        // Adding Cargo.toml auto-enables the whole-repo task.
        std::fs::write(tmp.path().join("Cargo.toml"), "").unwrap();
        std::fs::create_dir_all(tmp.path().join("workflows")).unwrap();
        assert_eq!(m.effective_tasks(tmp.path()), vec![PathBuf::from(".")]);
        assert_eq!(
            m.effective_workflows(tmp.path()),
            vec!["workflows/*.yml".to_string(), "workflows/*.yaml".into()]
        );
    }

    #[test]
    fn repo_manifest_yaml_overrides_defaults() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("secator.yml"),
            "name: test\ndescription: t\ntasks:\n  - subdir\nworkflows:\n  - wf/*.yml\n",
        )
        .unwrap();
        let m = RepoManifest::load(tmp.path());
        assert_eq!(m.name, "test");
        assert_eq!(m.effective_tasks(tmp.path()), vec![PathBuf::from("subdir")]);
        assert_eq!(m.effective_workflows(tmp.path()), vec!["wf/*.yml".to_string()]);
    }

    #[test]
    fn sync_one_rejects_empty_url() {
        let t = CustomTemplate::default();
        let r = sync_one(&t);
        assert!(matches!(r.status, SyncStatus::Failed(_)));
    }

    #[test]
    fn sync_one_reports_disabled() {
        let t = CustomTemplate {
            url: "https://example.com/x".into(),
            enabled: false,
            ..Default::default()
        };
        let r = sync_one(&t);
        assert!(matches!(r.status, SyncStatus::Disabled));
    }
}
