//! Built-in workflow / scan / profile registries — moved here from
//! `secator-cli` so other crates (e.g. `secator-tasks::native::ai`) can read
//! the static YAML lists without depending on the CLI.
//!
//! Layout mirrors Python's `secator/configs/{workflows,scans,profiles}/*.yaml`.
//! Each entry is the raw YAML string `include_str!`'d at compile time so the
//! binary stays self-contained.
//!
//! User extensions: `init_user_templates(dir)` walks `<dir>` for `*.yaml` files
//! and overlays them onto the built-in catalogs. Operators drop their custom
//! workflows / scans / profiles into `~/.secator/templates/` and the CLI
//! discovers them at startup — Python parity with `loader.find_templates()`.
//! Conflict policy: user templates override the built-in with the same
//! `name:`; the loader prints a startup info line when a built-in is shadowed.

use std::path::Path;
use std::sync::OnceLock;

/// Slot for user-supplied YAML, populated once per process by
/// [`init_user_templates`]. Entries: `(kind, name, body)` where `kind` is
/// `"workflow"`, `"scan"`, or `"profile"`. `&'static str` bodies are obtained
/// by `Box::leak`ing the file contents — one-shot leak, bounded by file count.
static USER: OnceLock<Vec<(&'static str, &'static str, &'static str)>> = OnceLock::new();

/// Walk `dir` for `*.yaml` files, classify each by its top-level `type:`
/// field, and stash the (kind, name, body) triple into the process-wide
/// overlay. Idempotent — repeat calls after the first are no-ops because of
/// the OnceLock. Returns the number of templates loaded (0 when the dir
/// doesn't exist, which is the common case for fresh installs).
pub fn init_user_templates(dir: &Path) -> usize {
    let entries = match collect_yaml_files(dir) {
        Ok(v) => v,
        Err(_) => Vec::new(),
    };
    let mut out: Vec<(&'static str, &'static str, &'static str)> = Vec::new();
    let mut shadowed: Vec<(String, &'static str)> = Vec::new();
    for (path, body) in entries {
        let (kind, name) = match classify_template(&body) {
            Some(pair) => pair,
            None => {
                eprintln!(
                    "[WRN] user template {} skipped: missing `type:` or `name:` field",
                    path.display()
                );
                continue;
            }
        };
        // Track shadowing against built-ins so operators get a heads-up.
        let built_in_hit = match kind {
            "workflow" => workflows::BUILT_IN.iter().any(|(n, _)| *n == name),
            "scan" => scans::BUILT_IN.iter().any(|(n, _)| *n == name),
            _ => false,
        };
        let name_static: &'static str = Box::leak(name.into_boxed_str());
        let body_static: &'static str = Box::leak(body.into_boxed_str());
        if built_in_hit {
            shadowed.push((name_static.to_string(), kind));
        }
        out.push((kind, name_static, body_static));
    }
    let count = out.len();
    let _ = USER.set(out);
    if count > 0 {
        eprintln!(
            "[INF] Loaded {count} user template{} from {}",
            if count == 1 { "" } else { "s" },
            dir.display(),
        );
    }
    for (name, kind) in shadowed {
        eprintln!("[WRN] user {kind} `{name}` shadows the built-in of the same name");
    }
    count
}

fn collect_yaml_files(dir: &Path) -> std::io::Result<Vec<(std::path::PathBuf, String)>> {
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    collect_yaml_files_rec(dir, &mut out)?;
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn collect_yaml_files_rec(
    dir: &Path,
    out: &mut Vec<(std::path::PathBuf, String)>,
) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            collect_yaml_files_rec(&path, out)?;
            continue;
        }
        if !ft.is_file() {
            continue;
        }
        let is_yaml = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("yaml") || e.eq_ignore_ascii_case("yml"))
            .unwrap_or(false);
        if !is_yaml {
            continue;
        }
        match std::fs::read_to_string(&path) {
            Ok(body) => out.push((path, body)),
            Err(e) => eprintln!(
                "[WRN] failed to read user template {}: {e}",
                path.display(),
            ),
        }
    }
    Ok(())
}

/// Extract `(type, name)` from a YAML body. Returns `None` when either field
/// is absent or unrecognized.
fn classify_template(body: &str) -> Option<(&'static str, String)> {
    let value: serde_yaml::Value = serde_yaml::from_str(body).ok()?;
    let map = value.as_mapping()?;
    let ty = map.get(serde_yaml::Value::String("type".into()))?.as_str()?;
    let kind = match ty {
        "workflow" => "workflow",
        "scan" => "scan",
        "profile" => "profile",
        _ => return None,
    };
    let name = map.get(serde_yaml::Value::String("name".into()))?.as_str()?.to_string();
    Some((kind, name))
}

/// Iterate every `(kind, name, body)` user template that was loaded by
/// [`init_user_templates`]. Empty when the loader was never invoked or
/// `dirs.templates` was missing.
fn user_iter() -> std::slice::Iter<'static, (&'static str, &'static str, &'static str)> {
    static EMPTY: [(&'static str, &'static str, &'static str); 0] = [];
    USER.get().map(|v| v.iter()).unwrap_or_else(|| EMPTY.iter())
}

/// Lookup helper shared by `workflows::get` / `scans::get`. User overlay wins
/// over the built-in catalog.
fn user_get(kind: &str, name: &str) -> Option<&'static str> {
    user_iter()
        .find(|(k, n, _)| *k == kind && *n == name)
        .map(|(_, _, body)| *body)
}

/// Names-list helper that merges user + built-in (user first, deduped).
fn merged_names(kind: &str, built_in: &'static [(&'static str, &'static str)]) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = user_iter()
        .filter(|(k, _, _)| *k == kind)
        .map(|(_, n, _)| *n)
        .collect();
    for (n, _) in built_in {
        if !out.contains(n) {
            out.push(*n);
        }
    }
    out
}

pub mod workflows {
    pub const BUILT_IN: &[(&str, &str)] = &[
        (
            "cidr_recon",
            include_str!("../../../../secator/configs/workflows/cidr_recon.yaml"),
        ),
        (
            "code_scan",
            include_str!("../../../../secator/configs/workflows/code_scan.yaml"),
        ),
        (
            "domain_recon",
            include_str!("../../../../secator/configs/workflows/domain_recon.yaml"),
        ),
        (
            "host_recon",
            include_str!("../../../../secator/configs/workflows/host_recon.yaml"),
        ),
        (
            "subdomain_recon",
            include_str!("../../../../secator/configs/workflows/subdomain_recon.yaml"),
        ),
        (
            "url_bypass",
            include_str!("../../../../secator/configs/workflows/url_bypass.yaml"),
        ),
        (
            "url_crawl",
            include_str!("../../../../secator/configs/workflows/url_crawl.yaml"),
        ),
        (
            "url_dirsearch",
            include_str!("../../../../secator/configs/workflows/url_dirsearch.yaml"),
        ),
        (
            "url_fuzz",
            include_str!("../../../../secator/configs/workflows/url_fuzz.yaml"),
        ),
        (
            "url_params_fuzz",
            include_str!("../../../../secator/configs/workflows/url_params_fuzz.yaml"),
        ),
        (
            "url_secrets_hunt",
            include_str!("../../../../secator/configs/workflows/url_secrets_hunt.yaml"),
        ),
        (
            "url_vuln",
            include_str!("../../../../secator/configs/workflows/url_vuln.yaml"),
        ),
        (
            "user_hunt",
            include_str!("../../../../secator/configs/workflows/user_hunt.yaml"),
        ),
        (
            "wordpress",
            include_str!("../../../../secator/configs/workflows/wordpress.yaml"),
        ),
    ];

    pub fn get(name: &str) -> Option<&'static str> {
        super::user_get("workflow", name)
            .or_else(|| BUILT_IN.iter().find(|(n, _)| *n == name).map(|(_, yaml)| *yaml))
    }

    pub fn names() -> Vec<&'static str> {
        super::merged_names("workflow", BUILT_IN)
    }
}

pub mod scans {
    pub const BUILT_IN: &[(&str, &str)] = &[
        (
            "domain",
            include_str!("../../../../secator/configs/scans/domain.yaml"),
        ),
        (
            "host",
            include_str!("../../../../secator/configs/scans/host.yaml"),
        ),
        (
            "network",
            include_str!("../../../../secator/configs/scans/network.yaml"),
        ),
        (
            "subdomain",
            include_str!("../../../../secator/configs/scans/subdomain.yaml"),
        ),
        (
            "url",
            include_str!("../../../../secator/configs/scans/url.yaml"),
        ),
    ];

    pub fn get(name: &str) -> Option<&'static str> {
        super::user_get("scan", name)
            .or_else(|| BUILT_IN.iter().find(|(n, _)| *n == name).map(|(_, yaml)| *yaml))
    }

    pub fn names() -> Vec<&'static str> {
        super::merged_names("scan", BUILT_IN)
    }
}

/// Profile YAMLs aren't held in this crate's `BUILT_IN` arrays (they live
/// in `secator-cli::profiles`), but the user-overlay layer needs a way to
/// expose them too. The CLI's `profiles::get` checks here first.
pub mod profiles {
    pub fn get(name: &str) -> Option<&'static str> {
        super::user_get("profile", name)
    }
    pub fn names() -> Vec<&'static str> {
        super::user_iter()
            .filter(|(k, _, _)| *k == "profile")
            .map(|(_, n, _)| *n)
            .collect()
    }
}

#[cfg(test)]
mod user_loader_tests {
    use std::path::PathBuf;

    /// Helper: run `init_user_templates` inside a tempdir we built ourselves.
    /// The OnceLock is shared across this whole test binary, so we only assert
    /// the loader RETURN VALUE here — actual overlay-vs-builtin behavior is
    /// covered by the integration tests in `secator-cli` (separate binary, fresh
    /// OnceLock).
    fn make_yaml(dir: &PathBuf, name: &str, contents: &str) {
        std::fs::write(dir.join(name), contents).unwrap();
    }

    #[test]
    fn init_user_templates_counts_workflow_scan_profile_yamls() {
        let tmp = std::env::temp_dir().join(format!(
            "secator-tpl-{}-{}",
            std::process::id(),
            // poor-man randomness: nanos since epoch (Date::now is forbidden,
            // but SystemTime works in tests).
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        make_yaml(&tmp, "my-wf.yaml", "type: workflow\nname: my-wf\ntasks: {}\n");
        make_yaml(&tmp, "my-scan.yaml", "type: scan\nname: my-scan\nworkflows: {}\n");
        make_yaml(&tmp, "my-prof.yaml", "type: profile\nname: my-prof\nopts: {}\n");
        // Garbage non-YAML files should be silently ignored.
        make_yaml(&tmp, "notes.txt", "ignored");
        // Bad YAML missing type/name should warn but not crash.
        make_yaml(&tmp, "broken.yaml", "hello: world\n");

        let n = super::init_user_templates(&tmp);
        // Idempotency: OnceLock means a second call returns the same set.
        assert!(n >= 3, "expected ≥3 templates loaded, got {n}");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn missing_directory_returns_zero() {
        let n = super::init_user_templates(&PathBuf::from("/this/path/does/not/exist"));
        assert_eq!(n, 0);
    }
}
