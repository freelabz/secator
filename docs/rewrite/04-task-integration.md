# Task Integration Contract

A "task" wraps an external security tool (or pure-Python logic) into Secator's unified
model. This is the most important extensibility contract to replicate: ~46 of ~50 tasks
are thin **declarative** subclasses of `Command`; the rest subclass `PythonRunner`.
Source: `secator/tasks/*.py`, base classes in `secator/tasks/_categories.py`,
engine in `secator/runners/command.py`.

A task is discovered because it is decorated with `@task()` (sets `cls.__task__ = True`)
and lives in `secator/tasks/`. External tasks are loaded from `CONFIG.dirs.templates`.

---

## 1. The two task bases

- **`Command`** — wraps a CLI tool. You declare *how the tool's CLI works* and *how to
  parse its output*; the engine builds the command line, runs the subprocess, streams
  and parses output, handles install/proxy/chunking.
- **`PythonRunner`** — no `cmd`; you override `yielder()` to `yield` `OutputType` objects
  (or dicts, which still flow through the conversion pipeline). Current Python tasks:
  `ai`, `urlparser`, `netdetect`, `prompt`. (`ai` is a full LLM agent — see
  `08-subsystems.md`.)

Both inherit the `Runner` hook/validator/option machinery (`02-architecture.md`).

---

## 2. Category base classes (`_categories.py`)

Tasks usually subclass a *category* rather than `Command` directly. A category bundles
a set of `meta_opts` (shared CLI options) and default `input_types`/`output_types`.

`OPTS` is a central registry of meta-option definitions keyed by canonical names
(`HEADER`, `DATA`, `DELAY`, `DEPTH`, `FILTER_CODES/REGEX/SIZE/WORDS`, `FOLLOW_REDIRECT`,
`MATCH_*`, `METHOD`, `PROXY`, `RATE_LIMIT`, `REQUEST`, `RETRIES`, `THREADS`, `TIMEOUT`,
`USER_AGENT`, `WORDLIST`, `PORTS`, `REPLAY_PROXY`, `TOP_PORTS`). Option *groups* compose
these into `OPTS_HTTP_BASE`, `OPTS_HTTP`, `OPTS_HTTP_FUZZERS`, `OPTS_RECON`,
`OPTS_RECON_PORT`, `OPTS_VULN`, etc.

| Category | meta_opts | default input_types | default output_types | Notes |
|---|---|---|---|---|
| `HttpBase` | OPTS_HTTP_BASE | [URL] | [Url] | `before_init` applies a raw HTTP request file |
| `Http` | OPTS_HTTP | [URL] | [Url] | base + match/filter options |
| `HttpCrawler` | OPTS_HTTP_CRAWLERS | [URL] | [Url] | |
| `HttpFuzzer` | OPTS_HTTP_FUZZERS | [URL] | [Url] | `enable_duplicate_check=False`; `profile` callable picks queue by wordlist size |
| `HttpParamsFuzzer` | + WORDLIST_PARAMS | | | |
| `Recon` | OPTS_RECON | — | [Subdomain, UserAccount, Ip, Port] | |
| `ReconDns/User/Ip/Port` | (+ port opts) | [HOST]/[USERNAME]/[CIDR]/[IP] | [Subdomain]/[UserAccount]/[Ip]/[Port] | |
| `Vuln` | OPTS_VULN | — | [Vulnerability] | static CVE/CPE helpers (`lookup_cve`, `match_cpes`, `get_cpe_fs`) |
| `VulnHttp/VulnCode/VulnMulti` | | [HOST]/[PATH]/[HOST] | [Vulnerability] | `VulnMulti` base for nmap/nuclei/msfconsole/search_vulns |
| `Tagger` | — | [URL] | [Tag] | base for gf/ph |
| `OSInt` | — | — | [UserAccount] | base for h8mail |

The `Vuln` category centralizes CVE enrichment: tasks call `lookup_cve(cve_id, *cpes)`
which tries local cache → external provider (`08-subsystems.md` §3) → CPE matching to
suppress false positives.

---

## 3. The declarative contract — class attributes

### A. Identity & input
- `cmd: str` — base command, may include static flags (`'httpx-toolkit -irh'`,
  `'bbot -y --allow-deadly --force'`). First token = `cmd_name` (used by the `which`
  install check). `None` for PythonRunner.
- `input_types: list[str] | None` — accepted target types (`autodetect_type` validated;
  `None` = accept anything). Unsupported targets are skipped by `_validate_inputs`.
- `input_type: str` — looser legacy single-type field (mostly superseded).
- `output_types: list[OutputType]` — emitted result classes. **Order matters**: used as
  the fallback try-order in `_convert_item_schema` when there's no discriminator/`_type`.
- `default_inputs` — if set (e.g. `''`), task may run with no inputs.
- `tags: list[str]` — categorization (also drives `get_command_category` → the
  `cat1/cat2` string shown in CLI help).

### B. Input wiring (`_build_cmd_input`)
- `input_flag` — for a **single** input. `OPT_PIPE_INPUT` → `echo <in> | cmd`; `None` →
  positional; else `cmd <flag> <in>`.
- `file_flag` — for **multiple** inputs (written to `<reports>/.inputs/<fqn>.txt`).
  `OPT_PIPE_INPUT` → `cat file | cmd`; `OPT_SPACE_SEPARATED` → inline; `None` →
  positional file; else `cmd <flag> <file>`.
- `file_eof_newline: bool`, `file_copy_sudo: bool`.
- `input_chunk_size: int` — `1` = one target per process (nmap, ffuf, searchsploit…);
  `-1` = no chunking (gf, dnsx); default from config. Drives `needs_chunking()`.

`OPT_NOT_SUPPORTED (-1)`, `OPT_PIPE_INPUT (-2)`, `OPT_SPACE_SEPARATED (-3)` (in
`definitions.py`) are **load-bearing sentinel constants**.

### C. Option schema grammar (`opts`, `meta_opts`)
Both are `{opt_name: opt_conf}`. The `opt_conf` keys a rewrite must support:

| Key | Meaning |
|---|---|
| `type` | `str`/`int`/`float`/`list`/`dict` or `click.Choice([...])` for enums. |
| `is_flag` | bool flag (emits flag name, no value). |
| `default` | default value (often from `CONFIG.*`). |
| `short` | CLI shorthand / alias. |
| `help` | help text. |
| `required` | bool. |
| `internal` | resolved but **not emitted to the command line** (e.g. `mode`, `output_path`). |
| `display` | whether shown in CLI help. |
| `pre_process` | callable applied to the raw value before mapping. |
| `process` | callable applied at command-build time to the final value. |
| `shlex` | shell-quote the value (default True). |
| `requires_sudo` | if the option is active, set `self.requires_sudo=True`. |
| `internal_name` | alternate attribute name to store the value under. |

### D. Option mapping
- `opt_prefix` — `-` (default) or `--`. `_`→`-` auto-conversion in names.
- `opt_key_map` — canonical opt → actual CLI flag. `OPT_NOT_SUPPORTED` drops it; a
  value starting with `-`/`--` is used verbatim; `''` emits the value with no flag.
- `opt_value_map` — opt → value transform (constant or callable). **Overrides**
  `pre_process`/`process` for that key (e.g. nuclei `tags: lambda x: ','.join(x)`,
  naabu `TIMEOUT: lambda x: int(x)*1000`).

Resolution (`_process_opts`/`_get_opt_value`): resolve value via aliases
(`<node_id>.opt`, `<node_name>.opt`, `<unique_name>.opt`, bare name, then `short`) →
skip falsy/unsupported → apply value-map or `pre_process` → map key → prefix →
`process` at build → emit `flag value` (or `flag` for flags, repeated for lists).

### E. Output flags & encoding
- `json_flag` — flag(s) to enable JSON output (`'-json'`, `'-jsonl'`, `'-f json'`,
  `'--json ndjson'`); each token shell-quoted. `None` if no JSON mode.
- `version_flag` — default `<prefix>version`; `OPT_NOT_SUPPORTED` disables.
- `encoding` — `'utf-8'` or `'ansi'` (strips ANSI per line — ffuf, msfconsole).
- `ignore_return_code` — treat nonzero exit as success (trufflehog, msfconsole).
- `shell`, `cwd`, `cwd_isolated`, `disable_preexec`, `requires_sudo`.

### F. Output parsing
Chain: **stdout line → `item_loaders` → dict/str → `validate_item` →
`on_item_pre_convert` → `_convert_item_schema` → `on_item`**.

- `item_loaders` — list of serializer instances and/or callables `(self, line)`.
- `item_loader` — a single instance method appended at init.
- **Serializers** (`secator/serializers/`):
  - `JSONSerializer(strict, list)` — extract `{...}`/`[{...}]` substring, `json.loads`.
  - `RegexSerializer(regex, fields, findall)` — match → named-group dict / raw matches.
- **Serializer callbacks**: a serializer named `XSerializer` triggers an optional
  `on_<x>_loaded(self, item)` per item (e.g. `on_json_loaded`) — the single most common
  transform point. Absent → passthrough.
- `output_map` — `{OutputTypeClass: {field: mapper}}`; mapper is a source-key string or
  a `lambda item: ...`. Consumed by `OutputType.load`. Unmapped fields fall through by
  name. All-None → load raises → next output type tried.
- `output_discriminator` — `(self, item) -> OutputTypeClass | None`; picks the single
  type to load as (nuclei: severity→Tag/Vulnerability/Progress; bbot: `type`→class).
  Absent → use `_type` key → else try `output_types` in order.

**Two output paradigms coexist:**
1. *Streaming* — `item_loaders` + `on_<serializer>_loaded` per line (most tools).
2. *File output* — `on_cmd_done` parses a JSON/XML file the tool wrote (often via an
   `internal` `output_path` opt + an injected `-o`/`-oX`/`-r` flag in `on_cmd`). Used by
   nmap (XML), gitleaks, trivy, maigret, h8mail.

### G. Proxy
- `proxychains: bool`, `proxychains_flavor: str` (nmap uses `proxychains4`),
  `proxy_socks5: bool`, `proxy_http: bool`. `configure_proxy()` resolves the global
  `proxy` opt (`auto`/`proxychains`/`socks5`/`http`/`random`/explicit URL).

### H. Profiles (queue/resource class)
`profile` — a string (`'small'`/`'medium'`/`'large'`/`'extra_large'`) **or a callable**
`(opts) -> str`. Used as the Celery queue for `.delay()/.s()/.si()`. (Also names YAML
option-preset bundles applied to tasks.)

### I. Install metadata (`installer.py::ToolInstaller.install`)
Order: `install_pre` (system packages) → GitHub release binary (if `github_handle` +
`install_github_bin` + not forced source) → on failure: `install_cmd_pre` + `install_cmd`
(source) → `install_post`.
- `install_cmd` — source build (supports `[install_version]` / `[install_version_strip]`
  placeholders; detects go/cargo/pip(x) to locate the binary).
- `install_version`, `install_pre` (`{pkg_mgr_glob: [pkgs]}`), `install_cmd_pre`,
  `install_post` (`{glob: cmd}`), `github_handle`, `install_github_bin`,
  `install_github_version_prefix`, `install_binary_name`, `install_ignore_bin`.
- **Known bug to carry/fix:** `install_pre_cmd` in `wpscan.py`/`x8.py` is a typo for
  `install_cmd_pre` and is silently ignored.

---

## 4. Hooks a task can override

Declared as methods named after the hook (auto-wired by `register_hooks`).

**Runner-level** (`HOOKS`): `before_init(self)`, `on_init(self)`, `on_start(self)`,
`on_end(self)`, `on_item_pre_convert(self, item: dict)->dict|None`,
`on_item(self, item)->OutputType|None`, `on_duplicate(self, item)`, `on_interval(self)`.

**Command-level**: `on_cmd(self)` (after cmd built — append flags, detect mode, inject
output-file flag), `on_cmd_opts(self, opts: dict)->dict`, `on_cmd_done(self)->generator`
(parse file output after exit), `on_line(self, line: str)->str|generator|None`.

**Serializer callbacks**: `on_<serializer>_loaded(self, item)`.

Hooks are skipped under `no_process`/`dry_run`; exceptions become `Error` results. User
hooks (from run opts) run after class hooks.

Common patterns to note:
- **Mode auto-detection** (gitleaks/trivy/trufflehog/grype/wpprobe): an `internal`
  `mode` `click.Choice` opt, auto-detected in `on_cmd` by inspecting the input
  (`.git` present, URL prefix, path exists), then the cmd string is rewritten to inject
  the subcommand.
- **Raw HTTP request** (HTTP categories): `before_init` reads a Burp-style request file
  and injects method/url/headers/data into run opts.

---

## 5. Validators

- `validate_input(self, inputs)->bool` — gate the whole run. Built-ins:
  `_validate_input_nonempty`, `_validate_chunked_input` (sync mode can't take >1 target
  without a file flag), `_validate_inputs` (input-type filtering). dnsx adds a DNS
  wildcard false-positive check.
- `validate_item(self, item)->bool` — per-item filter on the raw dict before conversion
  (subfinder drops localhost, feroxbuster keeps `type==response`). False → drop silently.

---

## 6. Task catalog (~50)

| Task | engine | input_types | output_types | purpose |
|---|---|---|---|---|
| ai | PythonRunner (LLM) | any | Ai + finding types + Target | AI pentest assistant |
| arjun | arjun | URL | Url, Tag | HTTP param discovery |
| arp | arp -a | (none) | Ip | read ARP cache |
| arpscan | arp-scan | CIDR/IP/HOST | Ip | ARP host discovery |
| bbot | bbot | HOST/IP/URL/PORT/ORG/USER/FILE | Vulnerability, Port, Url, Record, Ip | multipurpose OSINT/recon |
| bup | bup | URL | Url, Progress | 40X bypasser |
| cariddi | cariddi | URL/HOST/HOST_PORT | Url, Tag | crawl endpoints/secrets |
| dalfox | dalfox | URL | Vulnerability, Url | XSS scanner |
| dirsearch | dirsearch | URL/HOST/IP | Url | web path brute-force |
| dnsx | dnsx | HOST/CIDR/IP | Record, Ip, Subdomain | DNS toolkit (pipe, no chunk) |
| feroxbuster | feroxbuster | URL/HOST/IP | Url | recursive content discovery |
| ffuf | ffuf | URL/STRING | Url, Subdomain, Progress | web fuzzer |
| fping | fping | IP/HOST/CIDR | Ip | ICMP host discovery |
| gau | gau | URL/HOST | Url, Subdomain | fetch known URLs |
| getasn | getasn | IP/HOST | Tag | ASN lookup |
| gf | gf | any | Tag | grep-pattern matcher |
| gitleaks | gitleaks | PATH | Tag | secret scanner (file output) |
| gospider | gospider | URL | Url | web spider |
| grype | grype | PATH/STRING | Vulnerability | container/FS vuln scan |
| h8mail | h8mail | EMAIL | UserAccount | email breach lookup |
| httpx | httpx-toolkit | HOST/HOST_PORT/IP/URL/STRING | Url, Subdomain, Technology, Vulnerability, Tag | HTTP probe toolkit |
| jswhois | jswhois | HOST | Tag | WHOIS as JSON |
| katana | katana | URL/HOST/IP | Url, Tag, Technology | crawling framework |
| maigret | maigret | SLUG/STRING | UserAccount | username dossier |
| mapcidr | mapcidr | CIDR/IP/SLUG | Ip | CIDR operations |
| msfconsole | msfconsole | HOST/HOST_PORT/IP | (none) | Metasploit driver |
| naabu | naabu | HOST/IP | Port, Ip | port scanner |
| netdetect | PythonRunner | (none) | Tag, Ip | detect local CIDR |
| nmap | nmap | HOST/IP/CIDR/STRING | Port, Ip, Vulnerability, Technology, Exploit, Progress | network mapper (XML, NSE, sudo) |
| nuclei | nuclei | HOST/HOST_PORT/IP/URL | Vulnerability, Tag, Technology, Progress | YAML-DSL vuln scanner |
| ph | ph | URL/STRING | Tag | pattern/vuln scanner |
| prompt | PythonRunner | — | Tag | prompt the user |
| search_vulns | search_vulns | HOST | Vulnerability, Exploit | known-vuln search |
| searchsploit | searchsploit | STRING/SLUG | Exploit | ExploitDB search |
| sshaudit | ssh-audit | HOST/IP | Vulnerability, Tag | SSH audit |
| subfinder | subfinder | HOST | Subdomain | passive subdomain enum |
| testssl | testssl.sh | HOST/HOST_PORT/URL/IP | Certificate, Vulnerability, Ip, Tag | SSL/TLS scanner |
| trivy | trivy | PATH/STRING | Tag, Vulnerability | versatile scanner |
| trufflehog | trufflehog | PATH/URL/STRING/GCS/SLUG | Tag, Info | secret scanner |
| urlfinder | urlfinder | HOST/URL | Url | find URLs |
| urlparser | PythonRunner | URL | Tag, Url | extract URL params |
| wafw00f | wafw00f | URL/HOST/IP | Tag | WAF fingerprint |
| whoisdomain | whoisdomain | HOST | Domain | domain registration |
| whois | whois-go | HOST | Domain | WHOIS JSON |
| wpprobe | wpprobe | URL | Vulnerability, Tag | WP plugin enum |
| wpscan | wpscan | URL/HOST/IP | Vulnerability, Tag | WP scanner |
| x8 | x8 | URL | Url, Tag | hidden-param discovery |
| xurlfind3r | xurlfind3r | HOST/URL | Url | passive URL discovery |

---

## 7. Rewrite implications

- The declarative part of a task is a **data structure** (cmd template, option schema,
  key/value maps, input wiring sentinels, install metadata, parsing config). In Go/Rust,
  model it as a struct + maps; load built-in tasks from code and external ones from a
  manifest (YAML/TOML), since the Python `@task()` discovery won't survive a rewrite.
- The behavioral part is a **set of optional hook functions**; model as a trait/interface
  with default no-ops, or as registered closures keyed by event.
- Faithfully reproduce: the option resolution/aliasing rules, the three input sentinels,
  the `output_map`/`output_discriminator`/`load` dict→record mapper (including
  "all-None ⇒ try next type"), and the streaming-vs-file parsing duality.
- `profile`-as-callable and mode-auto-detection are small but real features; don't drop
  them.
