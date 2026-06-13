# Peripheral Subsystems

Reference for the supporting subsystems around the runner core. Each section gives the
purpose, the extension contract, and how it wires into the rest of the system.

> Terminology: "hooks" is overloaded. **Lifecycle hooks** (`on_init`, `on_item`, …) are
> the event mechanism (`02-architecture.md`). **Integration hooks / drivers**
> (`secator/hooks/`) are side-effecting callables *registered into* that mechanism.

---

## 1. Exporters (`secator/exporters/`)

**Purpose**: render/persist a built `Report` into a format.

**Contract** (`_base.py`): an `Exporter(report)` implements `send(self)` (duck-typed; no
ABC). It reads from `report.data` (`{'info': {...}, 'results': {type_name: [items]}}`),
`report.output_folder`, `report.runner`, `report.title`, `report.workspace_name`. Items
may be dicts or `OutputType`s; exporters re-hydrate dicts via `cls.load(item)`.

| Exporter | Output |
|---|---|
| `ConsoleExporter` | prints each item to stdout console (piping). |
| `CsvExporter` | `report_<type>.csv` per finding type; columns = dataclass fields. |
| `JsonExporter` | single `report.json` via the dataclass JSON encoder. |
| `TxtExporter` | `report_<type>.txt` per type; `str(item)`. |
| `TableExporter` | Rich tables grouped by type (uses `_table_fields`/`_sort_by`); console-only. |
| `MarkdownExporter` | `report_ai.md` from `Ai` items' `.content` (AI sessions only). |
| `GdriveExporter` | uploads to Google Sheets (depends on CSV output; needs gdrive addon). |

**Selection**: each runner has `default_exporters` from config
(`CONFIG.{tasks,workflows,scans}.exporters`, default `[json,csv,txt,markdown]`);
`--output a,b` overrides. `resolve_exporters()` dynamically imports `<Cap>Exporter`.
At runner end, `export_reports()` builds a `Report` and calls `report.send()` (each
exporter wrapped in try/except). Gated on `enable_reports and not no_process and not
dry_run`.

---

## 2. Integration hooks / drivers (`secator/hooks/`)

**Purpose**: push runner/finding data to external systems on lifecycle events.

**Contract**: each module exports a module-level `HOOKS` dict mapping **runner class →
{event_name: [callable, …]}**. Callable signatures: runner-level events
(`on_init/on_start/on_end/on_interval`) → `fn(self)`; item-level (`on_item/on_duplicate`)
→ `fn(self, item) -> item` (must return the item).

| Driver | Effect |
|---|---|
| `api` | POST/PUT runners + findings to a remote REST API (secator.cloud); stores ids in `runner.context`. |
| `discord` | webhook embeds; edits a runner message in place; threads per runner; severity/type filters. |
| `gcs` | uploads URL screenshot/response files to a GCS bucket on `Task.on_item`, rewrites field to `gs://`. Uses a background `Thread`. |
| `mongodb` | persists runners (`<type>s` collections) + findings (`findings`); workspace-wide duplicate tagging (`tag_duplicates` shared task); `get_results`/`load_finding(s)`. |

**Wiring**: `--driver a,b` (+ `CONFIG.drivers.defaults`) → validate against
`AVAILABLE_DRIVERS` + addon availability → `import_dynamic('secator.hooks.<d>', 'HOOKS')`
→ `deep_merge_dicts(*hooks)` → passed as `hooks=` to the runner. `register_hooks` merges
per-class and global entries into `resolved_hooks[event]`; `run_hooks` calls them
(errors → `Error` results; `on_interval` throttled by `backend_update_frequency`).

---

## 3. Providers (`secator/providers/`)

**Purpose**: fetch and normalize CVE/exploit data from external databases.

**Contract** (`_base.py`, NotImplementedError-style bases):
- `CVEProvider`: subclasses implement `lookup_cve(cve_id)` (and optionally `lookup_cpe`).
  Base provides cached `lookup_external_cve(cve_id, provider=…)` (dispatch by name) and
  `lookup_local_cve(cve_id)` (disk cache `<data>/cves/<id>.json` → `Vulnerability`).
- `ExploitProvider`: `lookup_exploit(id)`; base provides external/local dispatch.

`CONFIG.providers.defaults = {cve: circl, exploit: exploitdb, ghsa: ghsa}`.

| Provider | Source |
|---|---|
| `circl` (default CVE) | `vulnerability.circl.lu/api/cve/<id>`; maps CVE-JSON 5.0 → `Vulnerability` (severity, cvss, CWE tags, CPEs in extra_data); disk-caches. |
| `vulners` | vulners SDK + api_key (addon-gated); raw bulletin. |
| `ghsa` | scrapes `github.com/advisories/<id>` for the CVE, delegates to CVE provider, adds `ghsa` tag. |
| `exploitdb` | `exploit-db.com/exploits/<id>`; raw HTML. |

**Wiring**: tasks (nmap, grype, trivy, search_vulns) call `VulnMulti.lookup_cve(cve_id,
*cpes)` (in `_categories.py`): local cache → external provider → CPE matching to suppress
false positives. Applicability of a version to a CVE is decided by `cve.py` (§9).

---

## 4. Query (`secator/query/`)

**Purpose**: a pluggable read/count/update layer over stored findings with one
MongoDB-style query dialect across backends.

**Contract** (`_base.py` `QueryBackend`, ABC): ctor `(workspace_id, config, context)`;
subclasses implement `_execute_search/count/update`. `search/count/update` always inject
`get_base_query()` (workspace scoping) and strip client overrides of `PROTECTED_FIELDS`
(`_context.workspace_id`, `_context.workspace_duplicate`).

`QueryEngine` (`__init__.py`) selects a backend from `context['drivers']`: mongodb →
`MongoDBBackend`; else api → `ApiBackend`; else default `JsonBackend`.

| Backend | Storage |
|---|---|
| `JsonBackend` (default) | in-memory results, or scans `<reports>/<ws>/*/report.json`; implements a **client-side MongoDB query evaluator** (`$and/$or`, dotted nested fields on dicts/dataclasses, `$regex/$contains/$in/$gt/$gte/$lt/$lte/$ne`). |
| `MongoDBBackend` | passes query to `db.findings`. |
| `ApiBackend` | POSTs query to the API search endpoint. |

`utils.py` translates CLI queries: `parse_report_paths('scans/5,tasks/3')` →
`$or` filter; `python_expr_to_mongo()` parses a human DSL
(`vuln.severity_score > 7 && ...` → Mongo dict, supports `~=`→`$regex`, `&&`/`||`, raw
JSON passthrough). Used by `secator report show`, the AI `query_workspace` tool, and
`Report.build()`.

---

## 5. Serializers (`secator/serializers/`)

**Purpose**: turn raw tool output into structured items (line serializers), and
(de)serialize OutputTypes (dataclass serializer).

**Line-serializer interface**: `run(line) -> Iterator[item]`. Used by `Command` via
`item_loaders`; an optional per-task `on_<name>_loaded(self, item)` post-processes each.
- `JSONSerializer(strict, list)` — extract `{...}`/`[{...}]` substring → `json.loads`.
- `RegexSerializer(regex, fields, findall)` — match → named-group dict / raw matches.

**`dataclass.py`** — the OutputType (de)serialization layer:
- `DataclassEncoder` — JSON-encodes anything with `.toDict()`, plus `PosixPath`→str,
  datetime→isoformat.
- `dataclass_decoder`/`loads_dataclass` — `object_hook` re-hydrating dicts with `_type`
  via `cls.load()`.
- `dump_dataclass`/`dumps_dataclass`, `get_output_cls(type)`.

---

## 6. Installer (`secator/installer.py`)

**Purpose**: auto-install external tools and report version/health.

`ToolInstaller.install(tool_cls)` reads the task class's install attributes
(`04-task-integration.md` §3I) and runs, in order:
1. `install_pre` → `PackageInstaller` (OS packages).
2. **GitHub releases** (`GithubInstaller`) if `github_handle` + `install_github_bin` and
   not forced source and distro not ignored.
3. **Source** (`SourceInstaller`) fallback: `install_cmd_pre` then `install_cmd`.
4. `install_post`.

Strategies:
- `PackageInstaller` — detects distro (apt/pacman/apk/dnf/yum/zypper/brew/winget/choco/
  scoop) → `Distribution(pm_installer, …)`; config `{pm_name|*: [pkgs]}`, `distro:pkg`
  filtering, `SECATOR_PACKAGE_MANAGER` override; adds sudo/flock.
- `SourceInstaller` — runs an install command (string or `{distro: cmd}`); auto-installs
  build prereqs (rustup for cargo, golang-go for go, ruby/gems for gem, git);
  substitutes `[install_version]`/`[install_version_strip]`; locates the produced binary
  across GOBIN / cargo / pipx / `~/.local/bin`; optional symlink into `dirs.bin`.
- `GithubInstaller` — GitHub releases API (optional `cli.github_token`); maps OS/arch to
  asset names (prefers tar.gz then zip); downloads/unpacks, chmod, moves into `dirs.bin`.

`InstallerStatus` enum (`is_ok()` ⇔ SUCCESS or SKIPPED_OK). `get_version_info()` powers
`secator health` (missing/outdated/latest/bleeding classification).

---

## 7. Tree (`secator/tree.py`)

Covered in `05-config-templates.md` §3. Model: `TaskNode` / `RunnerTree`; built by
`build_runner_tree(config)`; rendered (`render_tree`), pruned by condition
(`prune_runner_tree`), walked (`walk_runner_tree`, `get_flat_node_list`). Used for CLI
option generation, display, and Celery-canvas construction.

---

## 8. AI subsystem (`secator/ai/` + `tasks/ai.py`)

A first-class autonomous pentesting agent exposed as the `ai` task (a `PythonRunner`).
Uses **litellm** (provider-agnostic LLM); gated on the `ai` addon. This is a large,
distinctive feature; a rewrite may treat it as an optional module.

**Agent loop** (`tasks/ai.py`):
1. Init: resolve model/key/mode/limits; build `ChatHistory`, optional
   `SensitiveDataEncryptor`, `PermissionEngine` (from `CONFIG.addons.ai.permissions`),
   an interactivity backend; auto-approve workspace targets.
2. Mode detection: a fast `intent_model` call classifies the prompt
   (`attack`/`chat`/`exploit`); sets system prompt + tool schemas.
3. `_run_loop` (≤ `max_iterations`): auto-compact context at 85%; `call_llm(..., tools,
   tool_choice=auto)`; parse tool calls → actions → **guardrails** → dispatch (single or
   thread-pool batch) → yield findings live → write truncated tool results back to
   history. Special actions: `query` grants extra iterations; `stop` saves + exits;
   `follow_up`/max-iter re-prompts the user and re-detects mode.
4. History saved to `<reports>/history.json` on every exit.

**Modules**:
- `tools.py` — OpenAI function-calling schemas for `run_task`, `run_workflow`,
  `run_shell`, `query_workspace`, `follow_up`, `add_finding` (+ `stop`); tool↔action maps.
- `actions.py` — `ActionContext` + `dispatch_action` handlers (each a **generator yielding
  OutputType items**). task/workflow → instantiate `Task`/`Workflow` and yield from it
  (recursion for `ai`); shell → `subprocess.run` with sanitized env; query →
  `QueryEngine`; add_finding → build/validate a finding. `check_guardrails` drives the
  ask-flow. `_run_batch` = parallel exec with a progress panel.
- `guardrails.py` — `PermissionEngine`: rule-based allow/deny/ask (deny > allow >
  runtime_allow > ask > default-deny). Rules like `target(...)`, `shell(cmd,…)`,
  `read(/path/*)`, `write(...)`, `task(*)`. Parses shell commands via safecmd/shfmt;
  checks network targets and file paths; session-scoped `runtime_allow` approvals.
- `interactivity.py` — `CLIBackend` (interactive menus), `RemoteBackend` (polls the DB
  for answers), `AutoBackend` (non-interactive; injects `stop`).
- `history.py` — `ChatHistory`: token-aware litellm message list; context-window
  detection, `should_compact` at 85%, LLM summarization, trimming, action budget.
- `encryption.py` — `SensitiveDataEncryptor`: reversible PII masking
  (email/ip/host → `[TYPE:hash]`) before sending to the LLM, decrypt on the way back.
- `prompts.py` — mode prompt templates with `${include}` resolution; builds a compact
  library reference (tasks/workflows/profiles/wordlists/output-types) into the system
  prompt.
- `session.py` — save/list/replay sessions from `history.json`.
- `utils.py` — `init_llm`, `call_llm` (retries, cost, `_repair_orphan_tool_uses`),
  `setup_ai`, follow-up prompt menu.

---

## 9. `cve.py` and `report.py`

**`cve.py` — version-affected matching** (not provider lookup). Pure functions deciding
whether a discovered version is affected by a CVE's `versions` array:
`is_version_affected` / `check_version_against_entry` handle CVE-JSON semantics
(`lessThan`, `lessThanOrEqual`, semver, `changes[].status`, wildcard/comma/`X to Y`
ranges, prose ranges). Helpers: `extract_software_and_version`, `compare_versions`
(packaging.version), `software_names_match`. Used by nuclei/url and the `Vuln` category.

**`report.py` — Report aggregation**. `Report(runner, title, exporters)`:
- `build(query, dedupe)`: assembles `data = {'info': {...runner subset...}, 'results':
  {type_name: [items]}}`, delegating filtering/dedup to `QueryEngine` (passing
  `runner.results` in-memory to avoid serialization). Results bucketed by
  `FINDING_TYPES + Target`.
- `send()`: instantiate each exporter with `self`, call `.send()` (exceptions isolated).
- `is_empty()`, `get_table_fields(output_type)`.

This `data` structure is the contract every exporter consumes.

---

## 10. Misc

- **`thread.py`** — `Thread` subclass that captures exceptions in `run()` as
  `Error.from_exception(e)` and **returns** them from `join()` (no raising). Used for
  background work (GCS uploads). A rewrite needs join-returns-error semantics.
- **`requests.py`** — module-level `requests.Session()` with urllib3 `Retry` (3 retries,
  backoff, on 408/429/5xx) mounted on http/https. A shared retrying HTTP client.
- **`rich.py`** — terminal/UI layer: two `Console`s (`console`→stderr,
  `console_stdout`→stdout, both `record=True`); `maybe_status` spinner; color maps;
  `build_table(...)` (used by TableExporter); interactive widgets `FullScreenPrompt` and
  `InteractiveMenu` (used by the AI prompts). Presentation concerns referenced by
  exporters and the AI subsystem.
