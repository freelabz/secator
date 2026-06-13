# Configuration, Templates, and the Workflow/Scan DSL

Two distinct configuration systems coexist and must not be confused:

1. **App config** (`secator/config.py`) — global runtime settings (dirs, celery, http,
   addons, security…). Pydantic-validated, loaded from `~/.secator/config.yml` + env.
2. **Templates** (`secator/template.py`, `secator/loader.py`, `secator/configs/*.yaml`) —
   the YAML definitions of **workflows**, **scans**, and **profiles** (and on-the-fly
   task configs). This is the user-facing DSL for composing tools.

---

## 1. App config (`config.py`)

A tree of `pydantic.BaseModel` (`StrictModel`, `extra='forbid'`) sections under
`SecatorConfig`. At import time `CONFIG` is parsed: defaults → user YAML
(`~/.secator/config.yml`) → env overrides → validation. The result is wrapped in a
`DotMap` subclass (`Config`) supporting `get`/`set`/`unset`/`save`/`print` with a dotted
keymap.

Key sections (defaults abbreviated):
- `dirs` — bin, share, data (`~/.secator`), and derived subdirs templates/reports/
  wordlists/cves/payloads/celery/… (auto-created at startup).
- `celery` — broker_url (`filesystem://` default), result_backend, timeouts, memory
  limit, worker concurrency knobs.
- `cli` — github_token, record, stdin_timeout, http header display toggles, date_format.
- `runners` — input_chunk_size (100), progress/stat/backend update frequencies, threads
  (50), skip_cve_search, remove_duplicates, chunk_rate_limit.
- `security` — allow_local_file_access, **auto_install_commands**, force_source_install,
  prompt_sudo_password.
- `http` — socks5/http proxy, store_responses, response_max_size_bytes, proxychains_command,
  default_header (UA).
- `tasks`/`workflows`/`scans` — `exporters` lists (default `[json,csv,txt,markdown]`);
  `tasks.overrides` lets you override any task-class attribute per task name.
- `profiles.defaults`, `drivers.defaults`, `workspace.default`, `providers.defaults`
  (`{cve: circl, exploit: exploitdb, ghsa: ghsa}`).
- `payloads`/`wordlists` — name→URL maps; can auto-download to data dir.
- `addons` — feature-gated integrations (gdrive, gcs, worker, mongodb, vulners, discord,
  api, ai), each with `enabled` + settings. `ai.permissions` holds the AI guardrail
  allow/deny/ask ruleset (see `08-subsystems.md`).

Override mechanisms a rewrite must keep:
- **Env overrides**: any `SECATOR_<UPPER_DOTTED_KEY>` env var sets the matching config
  key (type-coerced from the existing value's type).
- **`.env` autoloading** via python-dotenv.
- **Partial config**: only non-default values are persisted (`config save`).
- `download_files()` resolves name→(URL | `git+repo` | local path) into the data dir,
  honoring `offline_mode` and `security.allow_local_file_access`.

---

## 2. Templates (`template.py`, `loader.py`)

### TemplateLoader
`TemplateLoader(input=..., name=...)` is a `DotMap` subclass that loads a template from:
- `name='workflow/host_recon'` → looks up a loaded template by type+name.
- a dict (on-the-fly config, e.g. a task config built by `Command.__init__`).
- a `Path`/YAML string → parsed via `yaml.load`.

`toDict(serialize=True)` additionally computes and embeds the fully-resolved CLI option
schema (`opts`) via `get_config_options` (below) for non-profile templates.

### Discovery / loading (`loader.py`, all `@cache`d)
- `discover_internal_tasks()` — import every module in `secator/tasks/`, collect classes
  that subclass `Runner` and have `__task__`.
- `discover_external_tasks()` — import `*.py` under `CONFIG.dirs.templates` as external
  tasks.
- `find_templates()` — glob `*.y*ml` under `configs/` and `CONFIG.dirs.templates`, load
  each as a `TemplateLoader`.
- `get_configs_by_type('task'|'workflow'|'scan'|'profile')` — tasks are synthesized
  on-the-fly from their classes; others come from `find_templates()`.

This dynamic discovery is convenient in Python but a rewrite will likely replace it with
explicit registration (built-ins) + a manifest directory scan (external).

---

## 3. The runner tree (`tree.py`)

A workflow/scan YAML is parsed into a `RunnerTree` of `TaskNode`s
(`build_runner_tree`). Node types: `scan`, `workflow`, `group`, `task`. The tree is used
for:
- **CLI option generation** (`get_config_options` walks it),
- **display** (`render_tree` with `├─/└─` and per-type emoji),
- **pruning** (`prune_runner_tree` removes nodes whose `if:` condition is false against
  the given opts/targets — bottom-up, errs toward keeping),
- **execution** (`Workflow.build_celery_workflow` walks it to build the Celery canvas).

`_group` / `_group/<name>` keys in YAML become `group` nodes (parallel execution). When
descending into a workflow node, scan-level option prefixes are stripped (e.g.
`domain_recon_passive` → `passive`) so inner tasks see the expected option names.

---

## 4. The Workflow/Scan/Profile DSL (YAML schema)

### Workflow
```yaml
type: workflow
name: host_recon          # must match filename
alias: hostrec
description: Host reconnaissance
tags: [recon, network, http]
input_types: [ip, host, cidr_range]

options:                  # NEW options this workflow exposes on the CLI
  nuclei:  {is_flag: true, default: false, help: "Run nuclei scans (slow)"}
  scanners: {type: list, default: [nmap], help: "Port scanners"}

default_options:          # defaults pushed down to tasks

tasks:
  _group:                 # parallel group
    naabu:
      description: Find open ports
      if: "'naabu' in opts.scanners and not opts.passive"
    nmap/light:           # task '/variant' → same class, different node id
      if: "'nmap' in opts.scanners and not opts.passive"

  nmap:
    description: Detect services and versions
    version_detection: true       # task option override (static)
    targets_:                      # DYNAMIC input extractor (trailing _)
      - {type: port, field: host, condition: opts.scanners}
    ports_:
      - {type: port, field: port, condition: port.host in targets and opts.scanners}
    if: not opts.passive           # node condition

  httpx:
    targets_:
      - {type: port, field: '{host}:{port}'}   # formatted field
```

Key DSL elements:
- **`options`** — new CLI options the workflow adds; **`default_options`** — defaults
  applied to its tasks.
- **`tasks`** — ordered map of `task_name[/variant]` → option overrides. Order = chain
  order. `_group` / `_group/<name>` → parallel group.
- **`if: <expr>`** — node condition. Python `eval` with restricted builtins (`len`),
  namespace `{opts, targets}`. False → node skipped/pruned.
- **`<opt>_: [extractors]`** (trailing underscore) — **dynamic option/target**. Pulls
  values from prior results. `targets_` sets the task's inputs; `<opt>_` sets an option.
  An extractor is `{type, field, condition, group_by}` or the `"type.field"` shorthand:
  - `type` — output type to pull from (`port`, `url`, `vulnerability`, `tag`, `target`…).
  - `field` — field to extract; supports `{nested.key}` formatting and literal templates
    like `'{host}:{port}'` or `'{matched_at}~{id}'`.
  - `condition` — per-item filter (`eval`; supports `~=` regex-match and `item.<field>`).
  - `group_by` — aggregate extracted values into `value,value~key` buckets.

### Scan
```yaml
type: scan
name: host
profile: default
input_types: [host, ip]
workflows:
  host_recon:
  url_crawl:
    targets_: [url.url]
  url_vuln:
    targets_:
      - {type: url, field: url, condition: url.verified}
```
A scan is an ordered map of workflows (each with optional `if:` and `targets_`), chained
with results flowing forward. Scan-level `options` are merged into each workflow.

### Profile
```yaml
type: profile
name: aggressive
category: speed
description: "..."
enforce: false      # if true, overrides user-supplied values
opts:
  rate_limit: 10000
  delay: 0
```
A profile is a named bundle of option presets. `--profiles a,b` merges them into run
opts (non-enforced profiles only fill unset values; `enforce: true` ones override and are
applied last). 15 built-in profiles (aggressive/stealth/tor/passive/paranoid/…).

---

## 5. CLI option generation from templates (`get_config_options`)

This is the trickiest config logic. Given a runner config, it produces the flat set of
CLI options by walking the tree and, for each task node, pulling that task class's
`opts`/`meta_opts`, then resolving **defaults and name conflicts**:
- Defaults cascade: task class default < workflow `default_options` < node opts < config
  options.
- When the same option name appears in multiple tasks/nodes, names are disambiguated
  (`<node>.<opt>`, prefixes like `Shared task`, `Config`, `Meta`, `Task <name>`,
  `Workflow <name>`). Conflicting options get prefixed/renamed; shared ones get an
  `applies_to` set.
- The output (`normalized_opts`) is an OrderedDict of `opt_name → conf` with `prefix`
  (for help grouping), `short`, `default`, `default_from`, `reverse` (boolean default
  True → expose `--no-x`), etc.

`serialize_config_options` JSON-serializes this (types → names) so a template's resolved
option schema can be embedded and reused (e.g. by the API/AI library reference).

A rewrite needs to reproduce this option-flattening + conflict-resolution faithfully,
since it defines the entire CLI surface of every workflow/scan.

---

## 6. Built-in templates inventory

- **Workflows** (`configs/workflows/`): cidr_recon, code_scan, domain_recon, host_recon,
  subdomain_recon, url_bypass, url_crawl, url_dirsearch, url_fuzz, url_params_fuzz,
  url_secrets_hunt, url_vuln, user_hunt, wordpress.
- **Scans** (`configs/scans/`): domain, host, network, subdomain, url.
- **Profiles** (`configs/profiles/`): active, aggressive, all_ports, full, http_headless,
  http_record, hunt_secrets, insane, paranoid, passive, polite, sneaky, stealth, tor.
