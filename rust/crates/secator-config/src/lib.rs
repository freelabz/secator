//! Typed configuration + env overrides + directory layout.
//!
//! Maps to Python `secator/config.py`. The schema mirrors Python's `SecatorConfig`
//! 1:1 — section names + field names + defaults all align so a user's existing
//! `~/.secator/config.yml` (and any `SECATOR_*` env overrides) work unchanged
//! when they switch from the Python CLI to the Rust binary.
//!
//! Sources merge in this order (last wins):
//!   1. Built-in defaults (every struct's `Default` impl).
//!   2. `~/.secator/config.yml` (or the path passed to `load_from`).
//!   3. `SECATOR_<DOTTED_UPPER_KEY>` env vars (Python `apply_env_overrides`).
//!   4. `dirs.fill_derived()` resolves `dirs.reports` → `dirs.data/reports`, etc.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------- Process-wide config

static GLOBAL: OnceLock<Config> = OnceLock::new();

/// Install a process-wide config (idempotent — first call wins, mirrors Python module init).
pub fn set(config: Config) {
    let _ = GLOBAL.set(config);
}

/// Return the process-wide config, falling back to defaults if `set` was never called.
pub fn get() -> &'static Config {
    GLOBAL.get_or_init(Config::default)
}

// =========================================================================== Dirs

/// Python `Directories` — every operationally-relevant directory under
/// `~/.secator/`. Empty fields get auto-filled from `data` by
/// `fill_derived()` so operators rarely set them explicitly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dirs {
    #[serde(default = "default_bin_dir")]
    pub bin: PathBuf,
    #[serde(default = "default_share_dir")]
    pub share: PathBuf,
    #[serde(default = "default_data_dir")]
    pub data: PathBuf,
    #[serde(default)]
    pub templates: PathBuf,
    #[serde(default)]
    pub reports: PathBuf,
    #[serde(default)]
    pub wordlists: PathBuf,
    #[serde(default)]
    pub cves: PathBuf,
    #[serde(default)]
    pub payloads: PathBuf,
    #[serde(default)]
    pub performance: PathBuf,
    #[serde(default)]
    pub revshells: PathBuf,
    #[serde(default)]
    pub celery: PathBuf,
    #[serde(default)]
    pub celery_data: PathBuf,
    #[serde(default)]
    pub celery_results: PathBuf,
}

impl Default for Dirs {
    fn default() -> Self {
        let mut d = Dirs {
            bin: default_bin_dir(),
            share: default_share_dir(),
            data: default_data_dir(),
            templates: PathBuf::new(),
            reports: PathBuf::new(),
            wordlists: PathBuf::new(),
            cves: PathBuf::new(),
            payloads: PathBuf::new(),
            performance: PathBuf::new(),
            revshells: PathBuf::new(),
            celery: PathBuf::new(),
            celery_data: PathBuf::new(),
            celery_results: PathBuf::new(),
        };
        d.fill_derived();
        d
    }
}

impl Dirs {
    /// Mirror Python `set_default_folders`: `templates` → `<data>/templates`,
    /// `celery_data` → `<data>/celery/data` (underscore → `/`), etc.
    pub fn fill_derived(&mut self) {
        for (field, sub) in [
            (&mut self.templates, "templates"),
            (&mut self.reports, "reports"),
            (&mut self.wordlists, "wordlists"),
            (&mut self.cves, "cves"),
            (&mut self.payloads, "payloads"),
            (&mut self.performance, "performance"),
            (&mut self.revshells, "revshells"),
            (&mut self.celery, "celery"),
            (&mut self.celery_data, "celery/data"),
            (&mut self.celery_results, "celery/results"),
        ] {
            if field.as_os_str().is_empty() {
                *field = self.data.join(sub);
            }
        }
    }

    /// Create each configured directory on disk if missing.
    pub fn ensure_exists(&self) -> std::io::Result<()> {
        for p in [
            &self.data, &self.bin, &self.share, &self.reports, &self.templates,
            &self.wordlists, &self.cves, &self.payloads, &self.performance,
            &self.revshells, &self.celery, &self.celery_data, &self.celery_results,
        ] {
            std::fs::create_dir_all(p)?;
        }
        Ok(())
    }
}

fn default_data_dir() -> PathBuf {
    // Honor `SECATOR_DIRS_DATA` (Python read it at import time).
    if let Ok(p) = std::env::var("SECATOR_DIRS_DATA") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    dirs::home_dir().unwrap_or_default().join(".secator")
}

fn default_bin_dir() -> PathBuf {
    dirs::home_dir().unwrap_or_default().join(".local/bin")
}

fn default_share_dir() -> PathBuf {
    dirs::home_dir().unwrap_or_default().join(".local/share")
}

/// Public accessor for the persisted user-config location.
/// Mirrors Python's `~/.secator/config.yml`.
pub fn user_config_path() -> PathBuf {
    default_data_dir().join("config.yml")
}

/// Where `secator template sync` clones each `custom_templates:` entry — one
/// subdirectory per repo, slug'd via [`CustomTemplate::slug`].
pub fn custom_templates_dir() -> PathBuf {
    default_data_dir().join("custom")
}

// =========================================================================== Cli

/// Python `Cli` — knobs the operator-facing CLI consults at startup.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Cli {
    /// `$GITHUB_TOKEN` is read at default time so an unset config still picks
    /// up the operator's existing env (Python parity).
    pub github_token: String,
    pub record: bool,
    pub stdin_timeout: i64,
    pub show_http_response_headers: bool,
    pub show_command_output: bool,
    pub exclude_http_response_headers: Vec<String>,
    pub date_format: String,
}
impl Default for Cli {
    fn default() -> Self {
        Cli {
            github_token: std::env::var("GITHUB_TOKEN").unwrap_or_default(),
            record: false,
            stdin_timeout: 1000,
            show_http_response_headers: false,
            show_command_output: false,
            exclude_http_response_headers: vec![
                "connection".into(),
                "content_type".into(),
                "content_length".into(),
                "date".into(),
                "server".into(),
            ],
            date_format: "%m/%d/%Y".into(),
        }
    }
}

// ===================================================================== Transport

/// Broker / worker tuning. In Python this section is called `celery`; the Rust
/// rewrite renames it to `transport` since the implementation is no longer
/// Celery-specific. A `celery:` key is still accepted (with a deprecation
/// warning) so Python configs Just Work.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Transport {
    pub broker_url: String,
    pub broker_pool_limit: i64,
    pub broker_connection_timeout: f64,
    pub broker_visibility_timeout: i64,
    pub broker_transport_options: String,
    pub override_default_logging: bool,
    pub result_backend: String,
    pub result_backend_transport_options: String,
    pub result_expires: i64,
    pub task_acks_late: bool,
    pub task_send_sent_event: bool,
    pub task_reject_on_worker_lost: bool,
    pub task_max_timeout: i64,
    pub task_memory_limit_mb: i64,
    pub worker_max_tasks_per_child: i64,
    pub worker_prefetch_multiplier: i64,
    pub worker_send_task_events: bool,
    pub worker_kill_after_task: bool,
    pub worker_kill_after_idle_seconds: i64,
    pub worker_command_verbose: bool,
}
impl Default for Transport {
    fn default() -> Self {
        Transport {
            broker_url: "filesystem://".into(),
            broker_pool_limit: 10,
            broker_connection_timeout: 4.0,
            broker_visibility_timeout: 3600,
            broker_transport_options: String::new(),
            override_default_logging: true,
            result_backend: String::new(),
            result_backend_transport_options: String::new(),
            result_expires: 86_400,
            task_acks_late: false,
            task_send_sent_event: false,
            task_reject_on_worker_lost: false,
            task_max_timeout: 7200,
            task_memory_limit_mb: -1,
            worker_max_tasks_per_child: 20,
            worker_prefetch_multiplier: 1,
            worker_send_task_events: false,
            worker_kill_after_task: false,
            worker_kill_after_idle_seconds: -1,
            worker_command_verbose: false,
        }
    }
}

// ======================================================================= Runners

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Runners {
    pub input_chunk_size: i64,
    pub progress_update_frequency: i64,
    pub stat_update_frequency: i64,
    pub backend_update_frequency: i64,
    pub poll_frequency: i64,
    pub skip_cve_search: bool,
    pub skip_exploit_search: bool,
    pub skip_cve_low_confidence: bool,
    pub remove_duplicates: bool,
    pub threads: i64,
    pub prompt_timeout: i64,
    pub chunk_rate_limit: bool,
}
impl Default for Runners {
    fn default() -> Self {
        Runners {
            input_chunk_size: 100,
            progress_update_frequency: 20,
            stat_update_frequency: 20,
            backend_update_frequency: 5,
            poll_frequency: 5,
            skip_cve_search: false,
            skip_exploit_search: false,
            skip_cve_low_confidence: false,
            remove_duplicates: false,
            threads: 50,
            prompt_timeout: 20,
            chunk_rate_limit: true,
        }
    }
}

// ====================================================================== Security

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Security {
    pub allow_local_file_access: bool,
    pub auto_install_commands: bool,
    pub force_source_install: bool,
    pub prompt_sudo_password: bool,
}
impl Default for Security {
    fn default() -> Self {
        Security {
            allow_local_file_access: true,
            auto_install_commands: true,
            force_source_install: false,
            prompt_sudo_password: true,
        }
    }
}

// ========================================================================== Http

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Http {
    pub socks5_proxy: String,
    pub http_proxy: String,
    pub store_responses: bool,
    pub response_max_size_bytes: i64,
    pub proxychains_command: String,
    pub freeproxy_timeout: u64,
    pub default_header: String,
}
impl Default for Http {
    fn default() -> Self {
        Http {
            socks5_proxy: "socks5://127.0.0.1:9050".into(),
            http_proxy: "https://127.0.0.1:9080".into(),
            store_responses: true,
            response_max_size_bytes: 100_000,
            proxychains_command: "proxychains".into(),
            freeproxy_timeout: 1,
            default_header: "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36".into(),
        }
    }
}

// ======================================================================== Tasks

/// Python `Tasks { exporters, overrides }`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Tasks {
    pub exporters: Vec<String>,
    /// Per-task option overrides: `tasks.overrides.<task>.<opt>: value`.
    /// Read at schema-build time so a user with `tasks.overrides.nmap.threads: 100`
    /// gets that as the default whenever nmap is invoked.
    pub overrides: BTreeMap<String, BTreeMap<String, serde_yaml::Value>>,
}
impl Default for Tasks {
    fn default() -> Self {
        Tasks { exporters: default_exporters(), overrides: BTreeMap::new() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Workflows {
    pub exporters: Vec<String>,
}
impl Default for Workflows {
    fn default() -> Self { Workflows { exporters: default_exporters() } }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Scans {
    pub exporters: Vec<String>,
}
impl Default for Scans {
    fn default() -> Self { Scans { exporters: default_exporters() } }
}

fn default_exporters() -> Vec<String> {
    vec!["json".into(), "csv".into(), "txt".into(), "markdown".into()]
}

// ===================================================================== Profiles

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Profiles {
    pub defaults: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Drivers {
    pub defaults: Vec<String>,
}

// ===================================================================== Workspace

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Workspace {
    pub default: String,
}

// ====================================================================== Payloads

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Payloads {
    pub templates: BTreeMap<String, String>,
}
impl Default for Payloads {
    fn default() -> Self {
        let mut t = BTreeMap::new();
        t.insert("lse".into(), "https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh".into());
        t.insert("linpeas".into(), "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh".into());
        t.insert("sudo_killer".into(), "https://github.com/TH3xACE/SUDO_KILLER/archive/refs/heads/V3.zip".into());
        Payloads { templates: t }
    }
}

// ===================================================================== Wordlists

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Wordlists {
    pub defaults: BTreeMap<String, String>,
    pub templates: BTreeMap<String, String>,
    pub lists: BTreeMap<String, Vec<String>>,
}
impl Default for Wordlists {
    fn default() -> Self {
        let mut defaults = BTreeMap::new();
        defaults.insert("http".into(), "bo0m_fuzz".into());
        defaults.insert("dns".into(), "combined_subdomains".into());
        defaults.insert("http_params".into(), "burp-parameter-names".into());
        let mut templates = BTreeMap::new();
        templates.insert("bo0m_fuzz".into(),
            "https://raw.githubusercontent.com/Bo0oM/fuzz.txt/master/fuzz.txt".into());
        templates.insert("combined_subdomains".into(),
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/combined_subdomains.txt".into());
        templates.insert("directory_list_small".into(),
            "https://gist.githubusercontent.com/sl4v/c087e36164e74233514b/raw/c51a811c70bbdd87f4725521420cc30e7232b36d/directory-list-2.3-small.txt".into());
        templates.insert("burp-parameter-names".into(),
            "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/burp-parameter-names.txt".into());
        Wordlists { defaults, templates, lists: BTreeMap::new() }
    }
}

// ===================================================================== Providers

/// Python `Providers { defaults: Dict[str, str] }` — preferred provider name
/// per kind (`cve`, `exploit`, `ghsa`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Providers {
    pub defaults: BTreeMap<String, String>,
}
impl Default for Providers {
    fn default() -> Self {
        let mut d = BTreeMap::new();
        d.insert("cve".into(), "circl".into());
        d.insert("exploit".into(), "exploitdb".into());
        d.insert("ghsa".into(), "ghsa".into());
        Providers { defaults: d }
    }
}
impl Providers {
    pub fn cve(&self) -> &str {
        self.defaults.get("cve").map(String::as_str).unwrap_or("circl")
    }
    pub fn ghsa(&self) -> &str {
        self.defaults.get("ghsa").map(String::as_str).unwrap_or("ghsa")
    }
    pub fn exploit(&self) -> &str {
        self.defaults.get("exploit").map(String::as_str).unwrap_or("exploitdb")
    }
}

// ======================================================================== Addons

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Addons {
    pub gdrive: GdriveAddon,
    pub gcs: GcsAddon,
    pub worker: WorkerAddon,
    pub mongodb: MongodbAddon,
    pub vulners: VulnersAddon,
    pub ai: AiAddon,
    pub discord: DiscordAddon,
    pub api: ApiAddon,
    /// Rust extension (Python has no Slack addon).
    pub slack: SlackAddon,
}

/// Python `WorkerAddon { enabled }`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct WorkerAddon {
    pub enabled: bool,
}

/// Python `GoogleDriveAddon`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct GdriveAddon {
    pub enabled: bool,
    pub drive_parent_folder_id: String,
    pub credentials_path: String,
    /// Rust extension: scopes `gcloud auth print-access-token`. Optional.
    pub service_account_email: String,
}

/// Python `GoogleCloudStorageAddon`. Field name matches Python: `credentials_path`
/// (NOT `credentials_file` — earlier Rust drift, fixed for parity).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GcsAddon {
    pub enabled: bool,
    pub bucket_name: String,
    pub credentials_path: String,
    /// Rust extension: override the gcloud CLI path.
    pub gcloud_command: String,
    /// Rust extension: per-type list of fields the driver intercepts +
    /// uploads to the bucket (Python hard-codes the equivalent set).
    pub items_to_send: BTreeMap<String, Vec<String>>,
}
impl Default for GcsAddon {
    fn default() -> Self {
        let mut items = BTreeMap::new();
        items.insert(
            "url".into(),
            vec!["screenshot_path".into(), "stored_response_path".into()],
        );
        GcsAddon {
            enabled: false,
            bucket_name: String::new(),
            credentials_path: String::new(),
            gcloud_command: "gcloud".into(),
            items_to_send: items,
        }
    }
}

/// Python `MongodbAddon`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MongodbAddon {
    pub enabled: bool,
    pub url: String,
    pub update_frequency: u64,
    pub max_pool_size: u32,
    pub server_selection_timeout_ms: u64,
    pub max_items: i64,
    pub duplicate_main_copy_fields: Vec<String>,
}
impl Default for MongodbAddon {
    fn default() -> Self {
        MongodbAddon {
            enabled: false,
            url: "mongodb://localhost".into(),
            update_frequency: 60,
            max_pool_size: 10,
            server_selection_timeout_ms: 5000,
            max_items: -1,
            duplicate_main_copy_fields: vec![
                "screenshot_path".into(),
                "stored_response_path".into(),
                "is_false_positive".into(),
                "is_acknowledged".into(),
                "verified".into(),
                "tags".into(),
            ],
        }
    }
}

/// Python `VulnersAddon`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct VulnersAddon {
    pub enabled: bool,
    pub api_key: String,
}

/// Python `AiAddon` — full set including the permissions DSL.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AiAddon {
    pub enabled: bool,
    pub api_key: String,
    pub api_base: String,
    pub default_model: String,
    pub intent_model: String,
    pub temperature: f64,
    pub max_tokens: i64,
    pub max_tokens_total: i64,
    pub max_results: i64,
    pub user_response_timeout: i64,
    pub encrypt_pii: bool,
    /// Allow / deny / ask pattern lists (Python parity). Each entry is a
    /// resource-typed pattern like `shell(curl,grep,jq)` or `target(*)`.
    pub permissions: AiPermissions,
}
impl Default for AiAddon {
    fn default() -> Self {
        AiAddon {
            enabled: false,
            api_key: String::new(),
            api_base: String::new(),
            default_model: "claude-sonnet-4-6".into(),
            intent_model: "claude-haiku-4-5".into(),
            temperature: 0.7,
            max_tokens: 30_000,
            max_tokens_total: 100_000,
            max_results: 500,
            user_response_timeout: 600,
            encrypt_pii: true,
            permissions: AiPermissions::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AiPermissions {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    pub ask: Vec<String>,
}
impl Default for AiPermissions {
    fn default() -> Self {
        AiPermissions {
            allow: vec![
                "target({targets})".into(),
                "read({workspace}/*,/dev/null,/tmp/*)".into(),
                "write({workspace}/.outputs/*,/dev/null,/tmp/*)".into(),
                "shell(curl,wget,dig,whois,host,grep,cat,ls,head,tail,jq,wc,find,cd,git,diff,stat,du,df,tree,sort,uniq,cut,tr,echo,realpath,readlink,file,strings,xxd,base64,for,while,which,true,timeout,tee,cp,mv,mkdir,touch,chmod,sed,awk,xargs,docker,printf,redis-cli,nc,ncat,nmap,sqlmap,nikto,gobuster,feroxbuster,ffuf,socat,telnet,openssl,ssh,scp,rsync,ping,traceroute,tcpdump,ss,netstat)".into(),
                "task(*)".into(),
                "workflow(*)".into(),
            ],
            deny: vec![
                "target(169.254.169.254)".into(),
                "target(127.0.0.1)".into(),
                "target(localhost)".into(),
                "read(/etc/shadow)".into(),
                "read(~/.ssh/*)".into(),
                "read(~/.aws/*)".into(),
                "write(/etc/*)".into(),
                "write(/usr/*)".into(),
                "shell(rm -rf /*,dd,mkfs,env,printenv)".into(),
            ],
            ask: vec![
                "target(*)".into(),
                "shell(python,python3,bash,sh,exec,node,ruby,perl,gcc,g++,make,go,php,java,javac)".into(),
                "read(*)".into(),
                "write(*)".into(),
            ],
        }
    }
}

/// Python `DiscordAddon`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DiscordAddon {
    pub enabled: bool,
    pub webhook_url: String,
    pub bot_token: String,
    pub send_runner_updates: bool,
    pub send_findings: bool,
    pub finding_types: Vec<String>,
    pub min_severity: String,
}
impl Default for DiscordAddon {
    fn default() -> Self {
        DiscordAddon {
            enabled: false,
            webhook_url: String::new(),
            bot_token: String::new(),
            send_runner_updates: true,
            send_findings: true,
            finding_types: vec!["vulnerability".into()],
            min_severity: "high".into(),
        }
    }
}

/// Python `ApiAddon`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ApiAddon {
    pub enabled: bool,
    pub url: String,
    pub key: String,
    pub header_name: String,
    pub force_ssl: bool,
    pub timeout: u64,
    pub runner_create_endpoint: String,
    pub runner_update_endpoint: String,
    pub finding_create_endpoint: String,
    pub finding_update_endpoint: String,
    pub finding_search_endpoint: String,
    pub workspace_get_endpoint: String,
    pub workspace_delete_endpoint: String,
    pub runner_delete_endpoint: String,
}
impl Default for ApiAddon {
    fn default() -> Self {
        ApiAddon {
            enabled: false,
            url: "https://app.secator.cloud/api".into(),
            key: String::new(),
            header_name: "Bearer".into(),
            force_ssl: true,
            timeout: 60,
            runner_create_endpoint: "runners".into(),
            runner_update_endpoint: "runner/{runner_id}".into(),
            finding_create_endpoint: "findings".into(),
            finding_update_endpoint: "finding/{finding_id}".into(),
            finding_search_endpoint: "findings/_search".into(),
            workspace_get_endpoint: "workspace/{workspace_id}".into(),
            workspace_delete_endpoint: "workspace/{workspace_id}".into(),
            runner_delete_endpoint: "{runner_type}/{runner_id}".into(),
        }
    }
}

/// Rust extension — Python has no SlackAddon. Identical shape to `DiscordAddon`
/// so the operator's mental model carries over.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SlackAddon {
    pub enabled: bool,
    pub webhook_url: String,
    pub send_runner_updates: bool,
    pub send_findings: bool,
    pub finding_types: Vec<String>,
    pub min_severity: String,
}
impl Default for SlackAddon {
    fn default() -> Self {
        SlackAddon {
            enabled: false,
            webhook_url: String::new(),
            send_runner_updates: true,
            send_findings: true,
            finding_types: vec!["vulnerability".into()],
            min_severity: "high".into(),
        }
    }
}

// =============================================================== CustomTemplate

/// One entry in `custom_templates:` — a remote git URL that provides some mix
/// of task plugins (Rust crates), workflows, and scans. `secator template sync`
/// clones/pulls each entry, builds task crates whose git-ref has moved, and
/// exposes any `workflows/*.yml` / `scans/*.yml` at runtime.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CustomTemplate {
    /// Git URL (https or ssh). Required in practice — an empty string is
    /// treated as a no-op so `Default` remains derivable.
    pub url: String,
    /// Branch / tag / commit to check out. Defaults to `main` when empty.
    pub branch: String,
    /// `false` → skip this repo at sync + skip its built plugins at load.
    /// Missing entries default to `true`.
    pub enabled: bool,
    /// Optional operator-facing note.
    pub description: String,
}
impl Default for CustomTemplate {
    fn default() -> Self {
        CustomTemplate {
            url: String::new(),
            branch: String::new(),
            enabled: true,
            description: String::new(),
        }
    }
}

impl CustomTemplate {
    /// Effective branch: `main` when unset, honoring the operator's override.
    pub fn effective_branch(&self) -> &str {
        if self.branch.is_empty() {
            "main"
        } else {
            &self.branch
        }
    }

    /// Directory slug used under `~/.secator/custom/`. Deterministic per URL
    /// so `sync` finds the same clone on every invocation.
    ///
    /// Example: `https://github.com/user/repo.git` → `github.com-user-repo`.
    pub fn slug(&self) -> String {
        let s = self.url.trim();
        let s = s.strip_suffix('/').unwrap_or(s);
        let s = s.strip_suffix(".git").unwrap_or(s);
        let s = s
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_start_matches("ssh://")
            .trim_start_matches("git@");
        let s = s.replacen(':', "-", 1);
        let mut out = String::with_capacity(s.len());
        for ch in s.chars() {
            match ch {
                '/' | '\\' | ' ' => out.push('-'),
                c if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' => out.push(c),
                _ => out.push('-'),
            }
        }
        while out.starts_with('-') {
            out.remove(0);
        }
        out
    }
}

// =============================================================== Top-level Config

/// Top-level config — matches Python `SecatorConfig` 1:1 (same field names,
/// same nesting, same defaults). A `~/.secator/config.yml` written by Python
/// deserializes into this struct without any field renames.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    /// Python `debug: str` — comma/glob list of debug channels (e.g. `cve.*`).
    /// Honored at runtime by `secator-debug`.
    pub debug: String,
    pub dirs: Dirs,
    /// Broker/worker tuning. Accepts the legacy Python key `celery:` as an alias
    /// (with deprecation warning emitted by `load_from`).
    #[serde(alias = "celery")]
    pub transport: Transport,
    pub cli: Cli,
    pub runners: Runners,
    pub http: Http,
    pub tasks: Tasks,
    pub workflows: Workflows,
    pub scans: Scans,
    pub payloads: Payloads,
    pub wordlists: Wordlists,
    pub profiles: Profiles,
    pub drivers: Drivers,
    pub workspace: Workspace,
    pub addons: Addons,
    pub security: Security,
    pub providers: Providers,
    /// Third-party template packs (git-cloned repos providing tasks / workflows
    /// / scans). Managed via `secator template sync/add/remove`.
    pub custom_templates: Vec<CustomTemplate>,
    pub offline_mode: bool,
    /// Captures unknown keys for forward-compat. Currently only used to swallow
    /// fields a newer Python adds that Rust hasn't ported yet.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_yaml::Value>,
}

#[derive(Debug)]
pub enum ConfigError {
    Io(String),
    Parse(String),
}
impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(s) => write!(f, "config io: {s}"),
            ConfigError::Parse(s) => write!(f, "config parse: {s}"),
        }
    }
}
impl std::error::Error for ConfigError {}

impl Config {
    /// Defaults → user YAML at `~/.secator/config.yml` (if present) → env overrides
    /// → fill derived dirs. Idempotent. Mirrors Python module init.
    pub fn load() -> Result<Self, ConfigError> {
        let path = default_data_dir().join("config.yml");
        Self::load_from(if path.exists() { Some(&path) } else { None })
    }

    pub fn load_from(path: Option<&std::path::Path>) -> Result<Self, ConfigError> {
        let mut cfg: Config = if let Some(p) = path {
            let text = std::fs::read_to_string(p)
                .map_err(|e| ConfigError::Io(format!("read {}: {e}", p.display())))?;
            // Detect the legacy Python key `celery:` so we can warn before deserialization
            // consumes it through the `transport` alias.
            if let Ok(raw) = serde_yaml::from_str::<serde_yaml::Value>(&text) {
                if let Some(map) = raw.as_mapping() {
                    let has_celery = map.contains_key(serde_yaml::Value::String("celery".into()));
                    let has_transport =
                        map.contains_key(serde_yaml::Value::String("transport".into()));
                    if has_celery {
                        let suffix = if has_transport {
                            " (ignored — `transport:` takes precedence)"
                        } else {
                            ""
                        };
                        eprintln!(
                            "warning: config key `celery:` is deprecated, rename it to `transport:`{suffix} ({})",
                            p.display()
                        );
                    }
                }
            }
            serde_yaml::from_str(&text).map_err(|e| ConfigError::Parse(e.to_string()))?
        } else {
            Config::default()
        };
        // Fill derived dirs first so env overrides can reference the resolved paths.
        cfg.dirs.fill_derived();
        // Python `set_extras`: default transport result_backend to file://<celery_results>.
        if cfg.transport.result_backend.is_empty() {
            cfg.transport.result_backend =
                format!("file://{}", cfg.dirs.celery_results.display());
        }
        cfg.apply_env_overrides();
        // Re-fill derived in case env overrides changed `dirs.data`.
        cfg.dirs.fill_derived();
        Ok(cfg)
    }

    /// Apply `SECATOR_<DOTTED_KEY>` env variables, coercing values to the existing type.
    pub fn apply_env_overrides(&mut self) {
        let mut yaml = match serde_yaml::to_value(&self) {
            Ok(v) => v,
            Err(_) => return,
        };
        let mut keymap: BTreeMap<String, Vec<String>> = BTreeMap::new();
        build_keymap(&yaml, &mut Vec::new(), &mut keymap);
        let prefix = "SECATOR_";
        let mut any = false;
        for (key, val) in std::env::vars() {
            if let Some(suffix) = key.strip_prefix(prefix) {
                if let Some(path) = keymap.get(suffix) {
                    if set_yaml_path(&mut yaml, path, &val) {
                        any = true;
                    }
                }
            }
        }
        if any {
            if let Ok(c) = serde_yaml::from_value::<Config>(yaml) {
                *self = c;
            }
        }
    }

    pub fn save_to(&self, path: &std::path::Path) -> Result<(), ConfigError> {
        let text = serde_yaml::to_string(self).map_err(|e| ConfigError::Parse(e.to_string()))?;
        std::fs::write(path, text).map_err(|e| ConfigError::Io(e.to_string()))?;
        Ok(())
    }
}

// ----------------------------------------------------------- Helpers (env coerce)

fn build_keymap(
    node: &serde_yaml::Value,
    base: &mut Vec<String>,
    out: &mut BTreeMap<String, Vec<String>>,
) {
    if let serde_yaml::Value::Mapping(m) = node {
        for (k, v) in m {
            if let Some(key) = k.as_str() {
                base.push(key.to_string());
                out.insert(base.join("_").to_uppercase(), base.clone());
                build_keymap(v, base, out);
                base.pop();
            }
        }
    }
}

fn set_yaml_path(root: &mut serde_yaml::Value, path: &[String], value: &str) -> bool {
    fn walk(node: &mut serde_yaml::Value, path: &[String], val: &str) -> bool {
        if path.is_empty() {
            return false;
        }
        let mapping = match node.as_mapping_mut() {
            Some(m) => m,
            None => return false,
        };
        let key = serde_yaml::Value::String(path[0].clone());
        if let Some(child) = mapping.get_mut(&key) {
            if path.len() == 1 {
                *child = coerce(child, val);
                return true;
            }
            return walk(child, &path[1..], val);
        }
        false
    }
    walk(root, path, value)
}

fn coerce(existing: &serde_yaml::Value, raw: &str) -> serde_yaml::Value {
    use serde_yaml::Value;
    match existing {
        Value::Bool(_) => Value::Bool(matches!(
            raw.to_lowercase().as_str(),
            "true" | "1" | "yes" | "on"
        )),
        Value::Number(n) => {
            if n.is_i64() {
                if let Ok(i) = raw.parse::<i64>() {
                    return Value::Number(i.into());
                }
            }
            if let Ok(f) = raw.parse::<f64>() {
                return serde_yaml::from_str(&f.to_string())
                    .unwrap_or(Value::String(raw.to_string()));
            }
            Value::String(raw.to_string())
        }
        Value::Sequence(_) => Value::Sequence(
            raw.split(',')
                .filter(|s| !s.is_empty())
                .map(|s| Value::String(s.to_string()))
                .collect(),
        ),
        _ => Value::String(raw.to_string()),
    }
}

// =========================================================================== Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sensible() {
        let c = Config::default();
        assert!(!c.dirs.data.as_os_str().is_empty());
        assert_eq!(c.runners.input_chunk_size, 100);
        assert_eq!(c.runners.threads, 50);
        assert_eq!(c.transport.broker_url, "filesystem://");
        assert!(c.security.auto_install_commands);
        assert_eq!(c.providers.cve(), "circl");
        assert_eq!(c.providers.exploit(), "exploitdb");
        assert_eq!(c.cli.stdin_timeout, 1000);
        assert!(c.addons.ai.encrypt_pii);
    }

    #[test]
    fn derived_dirs_resolve_under_data() {
        let mut c = Config::default();
        c.dirs.data = PathBuf::from("/tmp/secator-test");
        c.dirs.reports = PathBuf::new();
        c.dirs.celery_data = PathBuf::new();
        c.dirs.revshells = PathBuf::new();
        c.dirs.payloads = PathBuf::new();
        c.dirs.fill_derived();
        assert_eq!(c.dirs.reports, PathBuf::from("/tmp/secator-test/reports"));
        assert_eq!(c.dirs.celery_data, PathBuf::from("/tmp/secator-test/celery/data"));
        assert_eq!(c.dirs.revshells, PathBuf::from("/tmp/secator-test/revshells"));
        assert_eq!(c.dirs.payloads, PathBuf::from("/tmp/secator-test/payloads"));
    }

    /// The big regression test: a `~/.secator/config.yml` written by Python
    /// loads cleanly into the Rust schema with every field landing on the
    /// right struct and the right type.
    #[test]
    fn python_config_yaml_round_trip() {
        let yaml = r#"
debug: cve.*
dirs:
  data: /tmp/secator-py-test
  payloads: /tmp/secator-py-test/custom-payloads
transport:
  broker_url: redis://localhost:6379/0
  task_max_timeout: 600
  task_memory_limit_mb: 1024
  worker_kill_after_idle_seconds: 30
cli:
  github_token: ghp_DUMMY
  date_format: '%Y-%m-%d'
  exclude_http_response_headers: [date, server]
runners:
  threads: 100
  skip_cve_low_confidence: true
  prompt_timeout: 60
http:
  socks5_proxy: socks5://10.0.0.1:1080
  store_responses: false
tasks:
  exporters: [json, markdown]
  overrides:
    nmap:
      threads: 100
      timing: 4
workflows:
  exporters: [json]
scans:
  exporters: [json, csv]
profiles:
  defaults: [aggressive]
drivers:
  defaults: [mongodb]
workspace:
  default: production
payloads:
  templates:
    custom: https://example.com/payload.sh
wordlists:
  defaults:
    http: my-fuzz
  templates:
    my-fuzz: https://example.com/words.txt
providers:
  defaults:
    cve: vulners
    exploit: exploitdb
addons:
  gdrive:
    enabled: true
    credentials_path: /opt/sa.json
    drive_parent_folder_id: abc123
  gcs:
    enabled: true
    bucket_name: my-bucket
    credentials_path: /opt/gcs-sa.json
  mongodb:
    enabled: true
    url: mongodb://mongo:27017
  ai:
    enabled: true
    default_model: openai/gpt-4o
    temperature: 0.2
    permissions:
      allow: ['task(*)']
      deny: ['shell(rm)']
      ask: ['shell(*)']
  worker:
    enabled: true
security:
  allow_local_file_access: false
offline_mode: true
"#;
        let cfg: Config = serde_yaml::from_str(yaml).expect("Python YAML must deserialize");
        // debug
        assert_eq!(cfg.debug, "cve.*");
        // dirs
        assert_eq!(cfg.dirs.data, PathBuf::from("/tmp/secator-py-test"));
        assert_eq!(cfg.dirs.payloads, PathBuf::from("/tmp/secator-py-test/custom-payloads"));
        // transport (Python's `celery:` is accepted via alias — see legacy_celery_key_alias)
        assert_eq!(cfg.transport.broker_url, "redis://localhost:6379/0");
        assert_eq!(cfg.transport.task_max_timeout, 600);
        assert_eq!(cfg.transport.task_memory_limit_mb, 1024);
        assert_eq!(cfg.transport.worker_kill_after_idle_seconds, 30);
        // cli (new section)
        assert_eq!(cfg.cli.github_token, "ghp_DUMMY");
        assert_eq!(cfg.cli.date_format, "%Y-%m-%d");
        assert_eq!(cfg.cli.exclude_http_response_headers, vec!["date".to_string(), "server".into()]);
        // runners (new fields)
        assert_eq!(cfg.runners.threads, 100);
        assert!(cfg.runners.skip_cve_low_confidence);
        assert_eq!(cfg.runners.prompt_timeout, 60);
        // http (default proxy override)
        assert_eq!(cfg.http.socks5_proxy, "socks5://10.0.0.1:1080");
        assert!(!cfg.http.store_responses);
        // tasks (was `exporters.tasks` in old Rust layout)
        assert_eq!(cfg.tasks.exporters, vec!["json".to_string(), "markdown".into()]);
        assert_eq!(
            cfg.tasks.overrides.get("nmap").and_then(|m| m.get("threads")),
            Some(&serde_yaml::Value::Number(100.into()))
        );
        // workflows / scans separate sections
        assert_eq!(cfg.workflows.exporters, vec!["json".to_string()]);
        assert_eq!(cfg.scans.exporters, vec!["json".to_string(), "csv".into()]);
        // profiles / drivers nested with `defaults`
        assert_eq!(cfg.profiles.defaults, vec!["aggressive".to_string()]);
        assert_eq!(cfg.drivers.defaults, vec!["mongodb".to_string()]);
        // workspace
        assert_eq!(cfg.workspace.default, "production");
        // payloads (new section)
        assert_eq!(
            cfg.payloads.templates.get("custom"),
            Some(&"https://example.com/payload.sh".to_string())
        );
        // wordlists (new section)
        assert_eq!(cfg.wordlists.defaults.get("http"), Some(&"my-fuzz".to_string()));
        assert_eq!(
            cfg.wordlists.templates.get("my-fuzz"),
            Some(&"https://example.com/words.txt".to_string())
        );
        // providers under `defaults` (Python layout)
        assert_eq!(cfg.providers.cve(), "vulners");
        assert_eq!(cfg.providers.exploit(), "exploitdb");
        // addons
        assert!(cfg.addons.gdrive.enabled);
        assert_eq!(cfg.addons.gdrive.credentials_path, "/opt/sa.json");
        assert!(cfg.addons.gcs.enabled);
        assert_eq!(cfg.addons.gcs.credentials_path, "/opt/gcs-sa.json"); // was `credentials_file`!
        assert!(cfg.addons.mongodb.enabled);
        // ai addon
        assert!(cfg.addons.ai.enabled);
        assert_eq!(cfg.addons.ai.default_model, "openai/gpt-4o");
        assert_eq!(cfg.addons.ai.temperature, 0.2);
        assert_eq!(cfg.addons.ai.permissions.allow, vec!["task(*)".to_string()]);
        assert_eq!(cfg.addons.ai.permissions.deny, vec!["shell(rm)".to_string()]);
        // worker addon
        assert!(cfg.addons.worker.enabled);
        // security
        assert!(!cfg.security.allow_local_file_access);
        // offline
        assert!(cfg.offline_mode);
    }

    #[test]
    fn env_overrides_match_python_keymap() {
        std::env::set_var("SECATOR_RUNNERS_THREADS", "200");
        std::env::set_var("SECATOR_SECURITY_AUTO_INSTALL_COMMANDS", "false");
        std::env::set_var("SECATOR_TRANSPORT_BROKER_URL", "redis://example.com");
        std::env::set_var("SECATOR_TASKS_EXPORTERS", "json,csv");
        std::env::set_var("SECATOR_PROFILES_DEFAULTS", "aggressive,passive");
        let cfg = Config::load_from(None).unwrap();
        assert_eq!(cfg.runners.threads, 200);
        assert!(!cfg.security.auto_install_commands);
        assert_eq!(cfg.transport.broker_url, "redis://example.com");
        assert_eq!(cfg.tasks.exporters, vec!["json".to_string(), "csv".into()]);
        assert_eq!(cfg.profiles.defaults, vec!["aggressive".to_string(), "passive".into()]);
        std::env::remove_var("SECATOR_RUNNERS_THREADS");
        std::env::remove_var("SECATOR_SECURITY_AUTO_INSTALL_COMMANDS");
        std::env::remove_var("SECATOR_TRANSPORT_BROKER_URL");
        std::env::remove_var("SECATOR_TASKS_EXPORTERS");
        std::env::remove_var("SECATOR_PROFILES_DEFAULTS");
    }

    #[test]
    fn transport_result_backend_defaults_to_celery_results_dir() {
        // Mirrors Python `set_extras`: if `transport.result_backend` is empty,
        // fill it with `file://<dirs.celery_results>`.
        let tmp = tempfile::tempdir().unwrap();
        let cfg_path = tmp.path().join("config.yml");
        std::fs::write(&cfg_path, "dirs:\n  data: /tmp/secator-rb-test\n").unwrap();
        let cfg = Config::load_from(Some(&cfg_path)).unwrap();
        assert!(cfg
            .transport
            .result_backend
            .starts_with("file:///tmp/secator-rb-test/celery/results"));
    }

    #[test]
    fn legacy_celery_key_alias() {
        // Python configs use `celery:` — must still deserialize into `transport`.
        // Direct deserialize avoids env-var pollution from parallel tests in this
        // module that twiddle SECATOR_TRANSPORT_*; the alias semantics live in
        // serde's derive, not in `load_from`.
        let yaml = "celery:\n  broker_url: redis://from-celery\n  task_max_timeout: 999\n";
        let cfg: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.transport.broker_url, "redis://from-celery");
        assert_eq!(cfg.transport.task_max_timeout, 999);
    }

    #[test]
    fn custom_template_slug_deterministic_per_url() {
        let mk = |url: &str| CustomTemplate { url: url.into(), ..Default::default() };
        assert_eq!(mk("https://github.com/user/repo").slug(), "github.com-user-repo");
        assert_eq!(mk("https://github.com/user/repo.git").slug(), "github.com-user-repo");
        assert_eq!(mk("https://github.com/user/repo/").slug(), "github.com-user-repo");
        assert_eq!(mk("git@github.com:user/repo.git").slug(), "github.com-user-repo");
        assert_eq!(mk("ssh://git@gitlab.example.com/team/pack").slug(), "gitlab.example.com-team-pack");
    }

    #[test]
    fn custom_template_effective_branch_defaults_to_main() {
        let t = CustomTemplate { url: "x".into(), ..Default::default() };
        assert_eq!(t.effective_branch(), "main");
        let t = CustomTemplate { url: "x".into(), branch: "dev".into(), ..Default::default() };
        assert_eq!(t.effective_branch(), "dev");
    }

    #[test]
    fn custom_templates_round_trip_yaml() {
        let yaml = r#"
custom_templates:
  - url: https://github.com/user/pack-a
    branch: main
    enabled: true
    description: recon workflows
  - url: git@github.com:user/pack-b.git
    branch: v0.2.0
    enabled: false
"#;
        let cfg: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.custom_templates.len(), 2);
        assert_eq!(cfg.custom_templates[0].url, "https://github.com/user/pack-a");
        assert_eq!(cfg.custom_templates[0].effective_branch(), "main");
        assert!(cfg.custom_templates[0].enabled);
        assert_eq!(cfg.custom_templates[0].description, "recon workflows");
        assert_eq!(cfg.custom_templates[1].url, "git@github.com:user/pack-b.git");
        assert!(!cfg.custom_templates[1].enabled);
        assert_eq!(cfg.custom_templates[1].slug(), "github.com-user-pack-b");
    }

    #[test]
    fn provider_accessors_return_defaults_when_missing() {
        let mut p = Providers { defaults: BTreeMap::new() };
        assert_eq!(p.cve(), "circl"); // default fallback
        p.defaults.insert("cve".into(), "vulners".into());
        assert_eq!(p.cve(), "vulners");
        assert_eq!(p.ghsa(), "ghsa");
        assert_eq!(p.exploit(), "exploitdb");
    }
}
