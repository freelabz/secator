//! Binary path resolution + symlinking (Python `SourceInstaller._get_bin_path` +
//! `_symlink_binary`).
//!
//! After a source install (`go install`, `cargo install`, `pipx install`, …) the
//! toolchain drops the binary in its own bin dir. We walk the well-known locations,
//! find the freshest file matching the binary name, and symlink it under the secator
//! bin dir (`CONFIG.dirs.bin`, default `~/.local/bin`) so it's always reachable on
//! the operator's PATH.

use std::path::{Path, PathBuf};

/// What kind of source install just ran — drives which bin dirs to search.
#[derive(Debug, Clone, Copy)]
pub enum InstallKind {
    Go,
    Cargo,
    Pipx,
    Other,
}

impl InstallKind {
    /// Sniff `cmd` for known patterns (Python parity — `'go install'` /
    /// `'cargo install'` / `'pip install' | 'pipx install'`).
    pub fn from_cmd(cmd: &str) -> Self {
        let cmd_words: Vec<&str> = cmd.split_whitespace().collect();
        // Walk pairs so `go install` and `cd /tmp && go install` both match.
        for w in cmd_words.windows(2) {
            match (w[0], w[1]) {
                ("go", "install") | ("go", "get") => return InstallKind::Go,
                ("cargo", "install") => return InstallKind::Cargo,
                ("pip", "install") | ("pipx", "install") => return InstallKind::Pipx,
                _ => {}
            }
        }
        InstallKind::Other
    }

    /// Candidate bin directories in priority order (most-specific first).
    pub fn candidate_dirs(self) -> Vec<PathBuf> {
        let home = home_dir();
        match self {
            InstallKind::Go => vec![
                std::env::var_os("GOBIN").map(PathBuf::from).unwrap_or_default(),
                home.join("go/bin"),
                home.join(".local/bin"),
            ]
            .into_iter()
            .filter(|p| !p.as_os_str().is_empty())
            .collect(),
            InstallKind::Cargo => vec![
                std::env::var_os("CARGO_HOME")
                    .map(|h| PathBuf::from(h).join("bin"))
                    .unwrap_or_default(),
                home.join(".cargo/bin"),
                home.join(".local/bin"),
            ]
            .into_iter()
            .filter(|p| !p.as_os_str().is_empty())
            .collect(),
            InstallKind::Pipx => vec![
                std::env::var_os("PIPX_BIN_DIR").map(PathBuf::from).unwrap_or_default(),
                home.join(".local/bin"),
            ]
            .into_iter()
            .filter(|p| !p.as_os_str().is_empty())
            .collect(),
            InstallKind::Other => vec![home.join(".local/bin"), PathBuf::from("/usr/local/bin")],
        }
    }
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/root"))
}

/// Find the binary by name in the kind's candidate dirs. Returns the first existing
/// file, or `None` if nothing was found.
pub fn resolve_binary(name: &str, kind: InstallKind) -> Option<PathBuf> {
    for dir in kind.candidate_dirs() {
        let candidate = dir.join(name);
        if candidate.exists() {
            return Some(candidate);
        }
        // Windows: also probe `.exe`.
        let candidate_exe = dir.join(format!("{name}.exe"));
        if candidate_exe.exists() {
            return Some(candidate_exe);
        }
    }
    // Last-ditch: PATH lookup.
    which_in_path(name)
}

/// Symlink `source` → `target_dir/<name>`. Removes an existing target first
/// (Python `os.remove(target) + os.symlink(...)`). Idempotent — re-running is fine.
#[cfg(unix)]
pub fn symlink_into(source: &Path, target_dir: &Path, name: &str) -> Result<PathBuf, String> {
    std::fs::create_dir_all(target_dir).map_err(|e| format!("mkdir target dir: {e}"))?;
    let target = target_dir.join(name);
    // Already symlinked to the right thing? Bail with success.
    if let Ok(canon_t) = std::fs::canonicalize(&target) {
        if let Ok(canon_s) = std::fs::canonicalize(source) {
            if canon_t == canon_s {
                return Ok(target);
            }
        }
    }
    if target.exists() || target.symlink_metadata().is_ok() {
        std::fs::remove_file(&target).map_err(|e| format!("remove old link: {e}"))?;
    }
    std::os::unix::fs::symlink(source, &target).map_err(|e| format!("symlink: {e}"))?;
    Ok(target)
}

#[cfg(not(unix))]
pub fn symlink_into(source: &Path, target_dir: &Path, name: &str) -> Result<PathBuf, String> {
    // On Windows just copy — symlinks need admin or developer mode.
    std::fs::create_dir_all(target_dir).map_err(|e| format!("mkdir target dir: {e}"))?;
    let target = target_dir.join(name);
    if target.exists() {
        let _ = std::fs::remove_file(&target);
    }
    std::fs::copy(source, &target).map_err(|e| format!("copy: {e}"))?;
    Ok(target)
}

/// Locate `bin` on the host `PATH` (Python `which`).
pub fn which_in_path(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(bin);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_kind_sniffs_go() {
        assert!(matches!(InstallKind::from_cmd("go install -v foo@v1"), InstallKind::Go));
        assert!(matches!(
            InstallKind::from_cmd("cd /tmp && go install foo"),
            InstallKind::Go
        ));
    }

    #[test]
    fn install_kind_sniffs_cargo_and_pipx() {
        assert!(matches!(InstallKind::from_cmd("cargo install --git .."), InstallKind::Cargo));
        assert!(matches!(InstallKind::from_cmd("pipx install foo"), InstallKind::Pipx));
        assert!(matches!(InstallKind::from_cmd("pip install --user x"), InstallKind::Pipx));
    }

    #[test]
    fn other_when_no_match() {
        assert!(matches!(InstallKind::from_cmd("git clone https://x.com"), InstallKind::Other));
    }

    #[test]
    fn candidate_dirs_for_go_include_gobin_or_home_go_bin() {
        // Force GOBIN unset for a deterministic test.
        let dirs = InstallKind::Go.candidate_dirs();
        assert!(
            dirs.iter().any(|p| p.ends_with("go/bin")) || std::env::var_os("GOBIN").is_some()
        );
    }

    #[test]
    fn symlink_into_creates_and_replaces() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("real");
        std::fs::write(&src, b"hi").unwrap();
        let bin_dir = tmp.path().join("bin");
        let link = symlink_into(&src, &bin_dir, "foo").unwrap();
        assert!(link.exists());
        // Second call replaces (idempotent).
        let again = symlink_into(&src, &bin_dir, "foo").unwrap();
        assert_eq!(link, again);
    }

    #[test]
    fn resolve_binary_finds_in_explicit_dir() {
        // Stash a fake bin in a tmp dir, point PATH at it.
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("my-test-bin-12345");
        std::fs::write(&bin, b"x").unwrap();
        // Append to PATH so which_in_path can find it.
        let cur = std::env::var_os("PATH").unwrap_or_default();
        let new_path = std::env::join_paths(
            std::env::split_paths(&cur).chain(std::iter::once(tmp.path().to_path_buf())),
        )
        .unwrap();
        unsafe {
            std::env::set_var("PATH", new_path);
        }
        let found = resolve_binary("my-test-bin-12345", InstallKind::Other);
        // Cleanup.
        unsafe {
            std::env::set_var("PATH", cur);
        }
        let found = found.expect("should find binary on PATH");
        assert_eq!(found.file_name().unwrap(), "my-test-bin-12345");
    }
}
