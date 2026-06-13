//! Install pipeline (Python `secator/installer.py` parity).
//!
//! Drives `secator install <task>`:
//!
//! 1. Detect host distro / package manager ([`detect_distro`]).
//! 2. Run `pre` system-package install (sudo, `flock` in `SECATOR_IN_WORKER` mode).
//! 3. If the task has a `github_handle` and `github_bin` is set, fetch the matching
//!    release asset and place the binary directly under [`InstallOptions::bin_dir`]
//!    ([`github::install_from_github`]). Skip to step 5 on success.
//! 4. Otherwise source install: install `cmd_pre` packages, detect & install build
//!    toolchain prereqs (`go`/`cargo`/`gem`/`git`), substitute `[install_version]`
//!    placeholders, exec `cmd`. Then resolve where the toolchain put the binary
//!    (`go/bin`, `~/.cargo/bin`, `~/.local/bin`, …) and symlink it into `bin_dir`
//!    ([`binary::resolve_binary`] + [`binary::symlink_into`]).
//! 5. Run `post` distro-keyed cleanup commands.

use std::path::PathBuf;
use std::process::{Command as StdCommand, Stdio};

use secator_runner::{DistroCommand, InstallSpec, PackageGroup, TaskSpec};

pub mod binary;
pub mod github;

// ----------------------------------------------------------------- Distribution

/// Host distribution + the package manager Secator should drive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Distribution {
    /// `distro` ID (e.g. `arch`, `ubuntu`, `alpine`, `cachyos`, `darwin`, `windows`).
    pub name: String,
    /// `linux` / `darwin` / `windows`.
    pub system: String,
    /// `apt` / `apk` / `pacman` / `dnf` / `yum` / `zypper` / `brew` / `winget` / `choco`.
    pub pm_name: String,
    /// Full install-cmd prefix (Python `pm_installer`, e.g. `pacman -S --noconfirm --needed`).
    /// Empty when the distro isn't supported.
    pub pm_install: String,
    /// Optional cleanup cmd appended after install (Python `pm_finalizer`).
    pub pm_finalizer: Option<String>,
}

impl Distribution {
    pub fn is_supported(&self) -> bool {
        !self.pm_install.is_empty()
    }
}

/// Detect host distro / package manager. Honors `SECATOR_PACKAGE_MANAGER` and reads
/// `/etc/os-release` on Linux (mirrors Python's `distro.like() or distro.id()` fallback).
pub fn detect_distro() -> Distribution {
    if let Ok(env_pm) = std::env::var("SECATOR_PACKAGE_MANAGER") {
        let pm = env_pm.trim().to_string();
        return Distribution {
            name: pm.clone(),
            system: std::env::consts::OS.into(),
            pm_name: pm.split_whitespace().next().unwrap_or("").to_string(),
            pm_install: pm,
            pm_finalizer: None,
        };
    }
    match std::env::consts::OS {
        "linux" => detect_linux(),
        "macos" => Distribution {
            name: "macos".into(),
            system: "darwin".into(),
            pm_name: "brew".into(),
            pm_install: "brew install".into(),
            pm_finalizer: None,
        },
        "windows" => detect_windows(),
        other => Distribution {
            name: other.into(),
            system: other.into(),
            pm_name: String::new(),
            pm_install: String::new(),
            pm_finalizer: None,
        },
    }
}

fn detect_linux() -> Distribution {
    let id_like = read_os_release_field("ID_LIKE");
    let id = read_os_release_field("ID");
    let distrib = id_like
        .as_deref()
        .or(id.as_deref())
        .map(|s| s.split_whitespace().next().unwrap_or(""))
        .unwrap_or("");
    let (pm_name, pm_install, pm_finalizer) = match distrib {
        "ubuntu" | "debian" | "linuxmint" | "popos" | "kali" => (
            "apt",
            "apt install -y --no-install-recommends",
            Some("rm -rf /var/lib/apt/lists/*"),
        ),
        "arch" | "manjaro" | "endeavouros" | "cachyos" => {
            ("pacman", "pacman -S --noconfirm --needed", None)
        }
        "alpine" => ("apk", "apk add --no-cache", None),
        "fedora" => ("dnf", "dnf install -y", Some("dnf clean all")),
        "centos" | "rhel" | "rocky" | "alma" => ("yum", "yum -y", Some("yum clean all")),
        "opensuse" | "sles" => ("zypper", "zypper -n", Some("zypper clean --all")),
        _ => ("", "", None),
    };
    Distribution {
        name: id.unwrap_or_default(),
        system: "linux".into(),
        pm_name: pm_name.into(),
        pm_install: pm_install.into(),
        pm_finalizer: pm_finalizer.map(String::from),
    }
}

fn detect_windows() -> Distribution {
    let install = if which("winget") {
        "winget install --disable-interactivity"
    } else if which("choco") {
        "choco install -y --no-progress"
    } else {
        "scoop install"
    };
    Distribution {
        name: "windows".into(),
        system: "windows".into(),
        pm_name: install.split_whitespace().next().unwrap_or("").into(),
        pm_install: install.into(),
        pm_finalizer: None,
    }
}

fn read_os_release_field(field: &str) -> Option<String> {
    let body = std::fs::read_to_string("/etc/os-release").ok()?;
    for line in body.lines() {
        if let Some((k, v)) = line.split_once('=') {
            if k == field {
                return Some(v.trim_matches('"').to_string());
            }
        }
    }
    None
}

fn which(bin: &str) -> bool {
    let path = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path) {
        if dir.join(bin).exists() {
            return true;
        }
    }
    false
}

// ----------------------------------------------------------------- Pattern matching

/// Find the packages whose pm-pattern matches `pm_name`. Patterns are `|`-joined PM
/// names; `"*"` matches any. First match wins (Python iteration order).
pub fn match_package_group<'a>(
    groups: &'a [PackageGroup],
    pm_name: &str,
) -> Option<&'a [&'static str]> {
    for (pat, pkgs) in groups {
        if pattern_matches(pat, pm_name) {
            return Some(*pkgs);
        }
    }
    None
}

/// Like `match_package_group` but the right-hand value is a single shell command.
pub fn match_distro_command<'a>(commands: &'a [DistroCommand], distro_name: &str) -> Option<&'a str> {
    for (pat, cmd) in commands {
        if pattern_matches(pat, distro_name) {
            return Some(*cmd);
        }
    }
    None
}

fn pattern_matches(pattern: &str, candidate: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    pattern.split('|').any(|p| p.trim() == candidate)
}

// ----------------------------------------------------------------- Version substitution

/// Substitute `[install_version]` (and `[install_version_strip]`, which strips a
/// leading `v`) in `cmd`. `version=None` ⇒ `"latest"`.
pub fn substitute_version(cmd: &str, version: Option<&str>) -> String {
    let v = version.unwrap_or("latest");
    let stripped = v.strip_prefix('v').unwrap_or(v);
    cmd.replace("[install_version]", v)
        .replace("[install_version_strip]", stripped)
}

// ----------------------------------------------------------------- Build prereqs

/// Build systems that may need to be present before a source `install_cmd` runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BuildSystem {
    Cargo,
    Go,
    Gem,
    Git,
}

/// Distinct build systems referenced by `cmd` (Python `re.findall(r'(cargo\s+|go\s+|gem\s+|git\s+)')`).
pub fn detect_build_systems(cmd: &str) -> Vec<BuildSystem> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for tok in cmd.split_whitespace() {
        let bs = match tok {
            "cargo" => BuildSystem::Cargo,
            "go" => BuildSystem::Go,
            "gem" => BuildSystem::Gem,
            "git" => BuildSystem::Git,
            _ => continue,
        };
        if seen.insert(bs) {
            out.push(bs);
        }
    }
    out
}

impl BuildSystem {
    /// System packages needed for this build system, keyed by package manager.
    pub fn packages(self) -> Vec<PackageGroup> {
        match self {
            BuildSystem::Cargo => vec![("*", &["curl"])],
            BuildSystem::Go => vec![("apt", &["golang-go"]), ("*", &["go"])],
            BuildSystem::Gem => vec![
                ("apk", &["ruby", "ruby-dev"]),
                ("pacman", &["ruby", "rubygems"]),
                ("apt", &["ruby-full", "rubygems"]),
            ],
            BuildSystem::Git => vec![("*", &["git"])],
        }
    }

    /// Optional bootstrap shell command to run if the toolchain isn't already on PATH.
    /// `cargo` needs the rustup installer when not present; the others rely on the
    /// system packages above.
    pub fn bootstrap_cmd(self) -> Option<&'static str> {
        match self {
            BuildSystem::Cargo => Some("curl https://sh.rustup.rs -sSf | sh -s -- -y"),
            _ => None,
        }
    }

    /// Binary name to probe on PATH to decide whether to bootstrap.
    pub fn probe_bin(self) -> &'static str {
        match self {
            BuildSystem::Cargo => "cargo",
            BuildSystem::Go => "go",
            BuildSystem::Gem => "gem",
            BuildSystem::Git => "git",
        }
    }
}

// ----------------------------------------------------------------- InstallStatus

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallStatus {
    Success,
    SkippedOk,
    NotSupported,
    UnknownDistribution,
    PreInstallFailed(String),
    BuildPrereqFailed(String),
    InstallFailed(String),
    PostFailed(String),
    /// GitHub release not found / asset doesn't match host / download failed.
    GithubReleaseFailed(String),
    /// Symlink step (toolchain bin → `bin_dir`) failed.
    SymlinkFailed(String),
}

impl InstallStatus {
    pub fn is_ok(&self) -> bool {
        matches!(self, InstallStatus::Success | InstallStatus::SkippedOk)
    }
}

// ----------------------------------------------------------------- Install options

#[derive(Debug, Clone, Default)]
pub struct InstallOptions {
    /// Print every command but don't run anything.
    pub dry_run: bool,
    /// Skip the confirmation prompt before running shell commands (Python default
    /// is interactive; CI typically passes `--yes`).
    pub yes: bool,
    /// Override the task's `install.version` (e.g. `--version latest`).
    pub version_override: Option<String>,
    /// Pre-detected distro (cheap to compute, but we expose it for tests).
    pub distro: Option<Distribution>,
    /// Stream subprocess stdout/stderr instead of capturing.
    pub verbose: bool,
    /// Where to write GitHub-release binaries / symlink toolchain output. `None`
    /// resolves to `secator_config::get().dirs.bin` (default `~/.local/bin`).
    pub bin_dir: Option<PathBuf>,
    /// Skip the GitHub-releases path even when `github_handle` + `github_bin` are
    /// set (Python `CONFIG.security.force_source_install`). Useful when an op
    /// wants to build from source for reproducibility.
    pub force_source: bool,
    /// Optional GitHub API token override (falls back to `SECATOR_CLI_GITHUB_TOKEN`).
    pub github_token: Option<String>,
}

// ----------------------------------------------------------------- Command runner

/// Backend the installer uses to execute shell commands. The default
/// (`exec_shell`) just spawns `sh -c <cmd>`; tests pass a `record_only` fn to
/// avoid touching the host.
pub type CommandFn = fn(cmd: &str, dry_run: bool) -> i32;

fn exec_shell(cmd: &str, dry_run: bool) -> i32 {
    if dry_run {
        eprintln!("[dry-run] {cmd}");
        return 0;
    }
    eprintln!("⚡ {cmd}");
    let status = StdCommand::new("sh")
        .arg("-c")
        .arg(cmd)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status();
    match status {
        Ok(s) => s.code().unwrap_or(1),
        Err(e) => {
            eprintln!("failed to spawn `sh -c`: {e}");
            127
        }
    }
}

// ----------------------------------------------------------------- High-level

/// Run the full install pipeline for a `TaskSpec`. Returns `NotSupported` when the
/// spec has no install metadata at all.
pub fn install_task(spec: &TaskSpec, opts: &InstallOptions) -> InstallStatus {
    install_with(&spec.install, &spec.name, opts, exec_shell)
}

/// Same as `install_task` but with an injectable command runner (for tests).
pub fn install_with(
    install: &InstallSpec,
    name: &str,
    opts: &InstallOptions,
    run: CommandFn,
) -> InstallStatus {
    if install.cmd.is_none() && install.pre.is_empty() && install.cmd_pre.is_empty()
        && install.post.is_empty() && install.github_handle.is_none()
    {
        return InstallStatus::NotSupported;
    }

    let distro = opts.distro.clone().unwrap_or_else(detect_distro);
    if !distro.is_supported() {
        return InstallStatus::UnknownDistribution;
    }

    let sudo_prefix: &str = if is_root() { "" } else { "sudo " };
    let bin_dir = opts
        .bin_dir
        .clone()
        .unwrap_or_else(|| secator_config::get().dirs.bin.clone());

    eprintln!("🔧 Installing {name} on {} (pm: {})", distro.name, distro.pm_name);
    secator_debug::debug!("install", "task={name} distro={} pm={}", distro.name, distro.pm_name);

    // 1. Pre packages.
    if let Some(pkgs) = match_package_group(install.pre, &distro.pm_name) {
        secator_debug::debug!("install.pre", "{name} packages: {:?}", pkgs);
        if let Err(msg) = run_pkg_install(pkgs, &distro, sudo_prefix, opts, run) {
            return InstallStatus::PreInstallFailed(msg);
        }
    }

    // 2. GitHub releases (preferred when the spec has a handle + github_bin).
    let mut placed_via_github = false;
    if !opts.force_source
        && install.github_bin
        && install.github_handle.is_some()
    {
        let handle = install.github_handle.unwrap();
        let version = opts.version_override.as_deref().or(install.version).unwrap_or("latest");
        if opts.dry_run {
            eprintln!("[dry-run] github release {handle} {version} -> {}", bin_dir.display());
            placed_via_github = true;
        } else {
            let gh_opts = github::GhOptions {
                handle,
                version,
                version_prefix: "",
                target_binary_name: None,
                dest_dir: &bin_dir,
                token: opts.github_token.as_deref(),
                timeout: std::time::Duration::from_secs(5),
                http: github::default_http(),
            };
            match github::install_from_github(&gh_opts) {
                Ok(path) => {
                    eprintln!("✓ GitHub release installed at {}", path.display());
                    placed_via_github = true;
                }
                Err(e) => {
                    // Per Python: GH failure falls through to source-build, not a
                    // hard error. We log so the operator knows why we're rebuilding.
                    eprintln!("ℹ GitHub release path failed ({e}); falling back to source build");
                }
            }
        }
    }

    // 3. Source install (with build prereqs) — runs unless GH already placed the bin.
    if !placed_via_github {
        if let Some(cmd_template) = install.cmd {
            // 3a. cmd_pre packages.
            if let Some(pkgs) = match_package_group(install.cmd_pre, &distro.pm_name) {
                if let Err(msg) = run_pkg_install(pkgs, &distro, sudo_prefix, opts, run) {
                    return InstallStatus::PreInstallFailed(msg);
                }
            }
            // 3b. Build-system prereqs (go/cargo/gem/git).
            for bs in detect_build_systems(cmd_template) {
                if which(bs.probe_bin()) {
                    continue;
                }
                if let Some(pkgs) = match_package_group(&bs.packages(), &distro.pm_name) {
                    if let Err(msg) = run_pkg_install(pkgs, &distro, sudo_prefix, opts, run) {
                        return InstallStatus::BuildPrereqFailed(format!("{:?}: {}", bs, msg));
                    }
                }
                if let Some(boot) = bs.bootstrap_cmd() {
                    if run(boot, opts.dry_run) != 0 {
                        return InstallStatus::BuildPrereqFailed(format!(
                            "{:?} bootstrap failed", bs
                        ));
                    }
                }
            }
            // 3c. Substitute version + exec.
            let version = opts.version_override.as_deref().or(install.version);
            let cmd = substitute_version(cmd_template, version);
            secator_debug::debug!("install.cmd", "{name} running: {cmd}");
            if run(&cmd, opts.dry_run) != 0 {
                return InstallStatus::InstallFailed(cmd);
            }

            // 3d. Resolve binary in toolchain dir, symlink into bin_dir.
            if !opts.dry_run {
                if let Err(msg) = symlink_after_source(cmd_template, name, &bin_dir) {
                    // Soft-warn rather than hard-fail — for tasks that produce
                    // non-standard artifact layouts (e.g. msfconsole already
                    // symlinks itself in the install_cmd) the resolver may not
                    // find anything, but the binary IS on PATH already.
                    eprintln!("ℹ {msg}");
                }
            }
        }
    }

    // 4. Post commands (distro-keyed).
    if let Some(post_cmd) = match_distro_command(install.post, &distro.name) {
        secator_debug::debug!("install.post", "{name} running: {post_cmd}");
        if run(post_cmd, opts.dry_run) != 0 {
            return InstallStatus::PostFailed(post_cmd.into());
        }
    }

    InstallStatus::Success
}

/// After a source install, locate the produced binary in its toolchain dir
/// (`go/bin`, `~/.cargo/bin`, …) and symlink it into the unified secator bin dir
/// (Python `_get_bin_path` + `_symlink_binary`). Returns `Err` with a human-readable
/// reason when we can't find the binary or symlink fails.
fn symlink_after_source(cmd: &str, name: &str, bin_dir: &std::path::Path) -> Result<(), String> {
    let kind = binary::InstallKind::from_cmd(cmd);
    let source = binary::resolve_binary(name, kind)
        .ok_or_else(|| format!("could not locate binary {name:?} after source install"))?;
    // Already in the target dir? Nothing to do.
    if source.parent().map(|p| p == bin_dir).unwrap_or(false) {
        return Ok(());
    }
    binary::symlink_into(&source, bin_dir, name)
        .map(|p| eprintln!("✓ Symlinked {} → {}", p.display(), source.display()))
        .map_err(|e| format!("symlink {} → {}: {e}", source.display(), bin_dir.display()))
}

/// Build `<sudo> <pm_install> <pkg ...>` and run it.
fn run_pkg_install(
    pkgs: &[&str],
    distro: &Distribution,
    sudo_prefix: &str,
    opts: &InstallOptions,
    run: CommandFn,
) -> Result<(), String> {
    if pkgs.is_empty() {
        return Ok(());
    }
    let pkgs_filtered: Vec<&str> = pkgs
        .iter()
        .filter_map(|p| {
            // `<distro>:<pkg>` syntax — only install when distro matches.
            if let Some((d, real)) = p.split_once(':') {
                if d == distro.name { Some(real) } else { None }
            } else {
                Some(*p)
            }
        })
        .collect();
    if pkgs_filtered.is_empty() {
        return Ok(());
    }
    let joined = pkgs_filtered.join(" ");
    // In worker mode the install needs serialising — two workers racing on
    // `apt install` corrupt the dpkg lock. Python prepends `flock /tmp/install.lock`;
    // we do the same when SECATOR_IN_WORKER is set.
    let flock = if std::env::var_os("SECATOR_IN_WORKER").is_some() {
        "flock /tmp/secator-install.lock "
    } else {
        ""
    };
    let cmd = format!("{flock}{sudo_prefix}{} {joined}", distro.pm_install);
    if run(&cmd, opts.dry_run) != 0 {
        return Err(cmd);
    }
    Ok(())
}

fn is_root() -> bool {
    // Best effort — `id -u` is universal but the env var works inside many CI sandboxes.
    if let Ok(uid) = std::env::var("UID") {
        return uid == "0";
    }
    StdCommand::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false)
}

// ----------------------------------------------------------------- Tests

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn version_substitution_handles_both_placeholders() {
        let out = substitute_version(
            "go install foo@[install_version] && echo [install_version_strip]",
            Some("v1.2.3"),
        );
        assert!(out.contains("foo@v1.2.3"));
        assert!(out.contains("echo 1.2.3"));
    }

    #[test]
    fn version_default_is_latest() {
        let out = substitute_version("foo@[install_version]", None);
        assert!(out.contains("foo@latest"));
    }

    #[test]
    fn package_group_matches_wildcard_last() {
        let groups: &[PackageGroup] = &[("apt", &["golang-go"]), ("*", &["go"])];
        assert_eq!(match_package_group(groups, "apt"), Some(&["golang-go"][..]));
        assert_eq!(match_package_group(groups, "pacman"), Some(&["go"][..]));
    }

    #[test]
    fn package_group_alternation_pipe_works() {
        let groups: &[PackageGroup] = &[("apt|apk", &["libpcap-dev"])];
        assert!(match_package_group(groups, "apt").is_some());
        assert!(match_package_group(groups, "apk").is_some());
        assert!(match_package_group(groups, "pacman").is_none());
    }

    #[test]
    fn build_systems_detected_uniquely() {
        let bs = detect_build_systems("git clone x && cd x && go install -v . && go build");
        assert_eq!(bs, vec![BuildSystem::Git, BuildSystem::Go]);
    }

    #[test]
    fn distro_command_lookup() {
        let cmds: &[DistroCommand] = &[("arch|alpine|cachyos", "sudo ln -sf /lib/x /lib/y")];
        assert!(match_distro_command(cmds, "arch").is_some());
        assert!(match_distro_command(cmds, "cachyos").is_some());
        assert!(match_distro_command(cmds, "ubuntu").is_none());
    }

    thread_local! {
        static RECORDED: RefCell<Vec<String>> = RefCell::new(Vec::new());
    }
    fn record_cmd(cmd: &str, _dry: bool) -> i32 {
        RECORDED.with(|r| r.borrow_mut().push(cmd.into()));
        0
    }

    #[test]
    fn install_with_runs_pre_then_cmd_then_post() {
        RECORDED.with(|r| r.borrow_mut().clear());
        let install = InstallSpec {
            version: Some("v1.7.0"),
            cmd: Some("go install -v github.com/x/y/cmd/y@[install_version]"),
            pre: &[("apk", &["chromium"])],
            cmd_pre: &[],
            post: &[("arch", "echo done")],
            github_handle: Some("x/y"),
            github_bin: true,
        };
        let opts = InstallOptions {
            distro: Some(Distribution {
                name: "arch".into(),
                system: "linux".into(),
                pm_name: "apk".into(),
                pm_install: "apk add --no-cache".into(),
                pm_finalizer: None,
            }),
            ..Default::default()
        };
        let status = install_with(&install, "test", &opts, record_cmd);
        assert_eq!(status, InstallStatus::Success);
        let cmds = RECORDED.with(|r| r.borrow().clone());
        assert!(cmds.iter().any(|c| c.contains("apk add --no-cache chromium")));
        assert!(cmds.iter().any(|c| c.contains("go install -v github.com/x/y/cmd/y@v1.7.0")));
        assert!(cmds.iter().any(|c| c == "echo done"));
    }

    #[test]
    fn install_with_returns_not_supported_when_empty() {
        let status = install_with(&InstallSpec::EMPTY, "nope", &InstallOptions::default(), record_cmd);
        assert_eq!(status, InstallStatus::NotSupported);
    }

    #[test]
    fn install_with_unknown_distro_short_circuits() {
        RECORDED.with(|r| r.borrow_mut().clear());
        let install = InstallSpec {
            cmd: Some("go install foo"),
            ..InstallSpec::EMPTY
        };
        let opts = InstallOptions {
            distro: Some(Distribution {
                name: "freebsd".into(),
                system: "freebsd".into(),
                pm_name: String::new(),
                pm_install: String::new(),
                pm_finalizer: None,
            }),
            ..Default::default()
        };
        let status = install_with(&install, "foo", &opts, record_cmd);
        assert_eq!(status, InstallStatus::UnknownDistribution);
    }

    #[test]
    fn distro_pattern_with_colon_filters_by_distro_name() {
        // `<distro>:<pkg>` syntax: only install on matching distro.
        RECORDED.with(|r| r.borrow_mut().clear());
        let install = InstallSpec {
            pre: &[("*", &["arch:base-devel", "ubuntu:build-essential", "git"])],
            ..InstallSpec::EMPTY
        };
        let opts = InstallOptions {
            distro: Some(Distribution {
                name: "arch".into(),
                system: "linux".into(),
                pm_name: "pacman".into(),
                pm_install: "pacman -S --noconfirm --needed".into(),
                pm_finalizer: None,
            }),
            ..Default::default()
        };
        let _ = install_with(&install, "x", &opts, record_cmd);
        let pre_cmd = RECORDED
            .with(|r| r.borrow().iter().find(|c| c.contains("pacman")).cloned())
            .expect("expected a pacman cmd");
        assert!(pre_cmd.contains("base-devel"));
        assert!(!pre_cmd.contains("build-essential"));
        assert!(pre_cmd.contains("git"));
    }
}
