# Secator Rust ↔ Python parity

Living tracker for the Rust rewrite. Update on every sprint that flips a cell
— append to the **Progress log** below and bump the relevant table.

Per-cell status (Python / Rust columns):
- ✅ — implemented and verified
- 🟡 — partial / behind a feature flag / known-incomplete
- ❌ — missing entirely (or only a stub crate)
- ➖ — N/A in that runtime

**State** column (row-level rollup):
- **Complete** — Rust matches Python (or the gap is intentional `➖` because the
  feature doesn't apply to that runtime).
- **Partial** — wired but with a known gap (Rust column shows 🟡).
- **Not implemented** — Rust column shows ❌ and the feature is genuinely missing.
- **Deferred by user** — explicitly skipped for now (e.g. Airflow, SQLite).

---

## Progress log

Newest first. Each entry: date · sprint slug · cells flipped · task IDs.

### 2026-06-17 · T1–T8 follow-up sprint — every queued parity gap closed
- **#170 T1 Workflow merge-priority sweep** → ✅ Confirmed the `ancestor_defaults` priority fix from #167 carries through every workflow; new regression test `ancestor_defaults_lose_to_parent_runtime_opts` pins the order.
- **#171 T2 transport.task_memory_limit_mb enforcement** → ✅ `spawn_sampler_with_limit` walks the process tree via sysinfo, emits `OutputItem::Error("task killed: subprocess tree RSS …")`, and kills the root pid on breach. 1-second poll cadence when only the limit is set. Test: `memory_limit_breach_emits_error`.
- **#172 T3 transport.worker_kill_after_task** → ✅ Worker poll loop signals `self_shutdown` after each `process_unit` when the config flag is set, allowing supervisors to recycle on every task. Test: `worker_kill_after_task_recycles_after_one_unit`.
- **#173 T4 addons.ai.intent_model** → ✅ New `classify_intent` helper calls the cheap intent model with the bundled `modes/_selection.txt` prompt, normalizes the response to chat/attack/exploit, falls back to "chat" on any failure. Schema gains `intent_model` opt with addon fallback. Tests: `classify_intent_returns_none_for_blank_prompt`, `intent_model_does_not_call_llm_in_dry_run`.
- **#174 T5 AI per-mode allowed_actions** → ✅ `build_tool_schemas(mode, is_subagent)` filters tool schemas via `get_mode_config(mode).allowed_actions` — chat no longer sees `run_task`/`run_workflow`, exploit no longer sees `query_workspace`/`follow_up`. Tests: `chat_mode_strips_run_task_and_run_workflow`, `exploit_mode_drops_query_and_follow_up`.
- **#175 T6 --proxy random** → ✅ New `freeproxy::random_proxy` queries proxyscrape's plain-text list, shuffles, probes up to 8 candidates against `generate_204`, returns the first live `http://ip:port`. `configure_proxy` honors `--proxy random` for tasks with `proxy_http` caps; drops the opt cleanly when no proxy is alive within `cfg.http.freeproxy_timeout`.
- **#176 T7 Console + jsonl exporters** → ✅ Added `JsonlExporter` (writes `report.jsonl`) and `ConsoleExporter` (streams to stdout, returns empty paths so the CLI skips the "Saved" log line). Both register via `-o jsonl` / `-o console`. Tests: `jsonl_exporter_writes_one_object_per_line`, `console_exporter_returns_empty_paths`, `resolve_picks_jsonl_and_console`.
- **#177 T8 Release polish** → ✅ Added `secator template scaffold <name>` that drops a starter cdylib plugin crate under `~/.secator/templates/<name>/` and registers it in a top-level workspace `Cargo.toml`; added the `docker-rust.yml` GitHub Actions workflow that publishes `ghcr.io/freelabz/secator-rs` on `rust-dev` pushes + `rust-v*` tags. Tests: `scaffold_writes_full_skeleton_and_workspace_member`, `scaffold_rejects_bad_names`.
- **Full workspace suite**: 569 passed (1 ignored). No regressions.

### 2026-06-13 · Report-parity follow-ups — all 6 bugs fixed
- **#167 B-WF-PASSIVE** (HIGH) → ✅ Fixed by splitting `TaskPlan` into `ancestor_defaults` (lowest priority) and `opts` (highest priority). Exec merge is now `ancestor_defaults < parent_runtime_opts < own_opts` — workflow `options.passive.default: false` no longer clobbers `--pf passive`. Regression test `ancestor_defaults_lose_to_parent_runtime_opts` pins the priority. Live verified: `workflow url_crawl https://example.com --pf passive` now runs xurlfind3r.
- **#164 B-TASK-META** → ✅ Added `stamp_task_meta` helper called on every item in the single-task receive loop; fills `_source`, `_timestamp`, `_uuid`, `_context.workspace_{name,id}`.
- **#165 B-INFO-OPTS** → ✅ Workflow / scan paths now call `finalize_run_with_timing` with the captured initial_opts (via `opts_to_run_opts`) instead of `BTreeMap::new()`.
- **#168 B-TARGET-EMIT** → ✅ Both task and workflow paths emit one `Target` item per CLI input before the receive loop, stamped with `_source` = run name.
- **#166 B-INFO-CONTEXT** → ✅ `info.context` now carries `workspace_name`, `workspace_id`, `workspace_explicit`, and `drivers` (list of enabled driver names).
- **#169 B-EMPTY-REPORT** → ✅ Dropped the `if !report.is_empty()` gate in `finalize_run_with_timing` — `report.json` is written even for 0-finding runs.

### 2026-06-13 · S4 — Python/Rust report.json side-by-side comparison
- Ran `task jswhois example.com` and `workflow url_crawl https://example.com -pf passive` on both runtimes; diffed the resulting `report.json`. — #163
- Surfaced 6 schema- or behavior-level discrepancies + 4 documented Rust-only `info` extras. Full breakdown in `rust/PARITY_REPORT_COMPARISON.md`.
- Filed: #164 B-TASK-META · #165 B-INFO-OPTS · #166 B-INFO-CONTEXT · #167 B-WF-PASSIVE · #168 B-TARGET-EMIT · #169 B-EMPTY-REPORT (all subsequently resolved — see above)

### 2026-06-13 · S1 / S2 / S3 — Dockerfile + dynamic templates + plugin loader
- Rust Dockerfile (`rust/Dockerfile` + `Dockerfile.dev` + `.dockerignore`) → Not implemented → ✅ Complete — #160
- Dynamic workflow / scan / profile YAML from `~/.secator/templates/` → Not implemented → ✅ Complete — #161
- Dynamic Rust task / driver / exporter plugin system (`.rs` → cdylib via `cargo build --release` → `libloading` dlopen → `secator_plugin_v1_register`) → Not implemented → ✅ Complete — #162
- `secator template build|list|path` CLI subcommand → ✅ new — #162
- `secator-plugin-api` crate (stable surface for plugins) → ✅ new — #162

### 2026-06-13 · P3 / P4 / P5 config-wiring sprint
- `runners.input_chunk_size` config fallback → ✅ (was 🟡) — #153
- `runners.remove_duplicates` report-build gate → ✅ — #153
- `runners.chunk_rate_limit` per-chunk rate-limit split → ✅ — #153
- `runners.skip_cve_low_confidence` filter (nmap + search_vulns) → ✅ — #154
- `runners.prompt_timeout` native prompt timeout via helper thread → ✅ — #154
- `security.force_source_install` fallback in both install paths → ✅ — #155
- `tasks.overrides.<task>.<opt>` runtime merge → ✅ — #155
- `cli.show_command_output` → `--verbose` default OR → ✅ — #156
- Top-level `debug:` field seeds `secator_debug::init()` → ✅ — #156
- `transport.task_max_timeout` enforcement (`tokio::time::timeout` + `kill_on_drop`) → ✅ — #157
- `transport.worker_max_tasks_per_child` self-shutdown → ✅ — #157
- `transport.worker_kill_after_idle_seconds` watchdog → ✅ — #157
- `transport.task_memory_limit_mb` field plumbed → 🟡 (enforcement #159)
- `addons.ai.*` config fallback for AI task opts → ✅ — #158

### 2026-06-13 · Live demo + bug triage
- `Plan::Group` parallel remote dispatch end-to-end validated → ✅ — #150 (initial bug report was cross-broker Python-worker contention, not a Rust bug)
- SKIPPED `State` emitted on `if:` false / empty-inputs / unknown-class → ✅ — #151

### Earlier sprints (rolled-up, not exhaustive)
- Config schema 1:1 with Python `config.py`; rename `celery` → `transport` with deprecation alias and round-trip test
- True parallel `_group` execution via `futures::future::join_all`
- AI workflow dispatch via DAG → `LocalTransport` (replaces flattened serial)
- AI agent: history pruning, follow_up TTY/non-TTY, model registry, Mongo dedup, sessions, sub-agent depth cap
- Revshell pages + vuln lookup CLI + diff CLI + auto-install + GDrive exporter

---

## Open follow-ups linked from cells

| ID | Title | Severity |
|---|---|---|
| #152 | Document Python/Rust broker-dir collision risk | low |
| #159 | Wire `transport.task_memory_limit_mb` enforcement (sampler kill-path) | medium |
| ~~#164~~ | ~~B-TASK-META~~ — resolved ✅ | ~~medium~~ |
| ~~#165~~ | ~~B-INFO-OPTS~~ — resolved ✅ | ~~medium~~ |
| ~~#166~~ | ~~B-INFO-CONTEXT~~ — resolved ✅ | ~~low~~ |
| ~~#167~~ | ~~B-WF-PASSIVE~~ — resolved ✅ | ~~high~~ |
| ~~#168~~ | ~~B-TARGET-EMIT~~ — resolved ✅ | ~~medium~~ |
| ~~#169~~ | ~~B-EMPTY-REPORT~~ — resolved ✅ | ~~medium~~ |

---

## 1. Tool integrations

50 tasks in Python; 44 external + 4 native in Rust (48 of 48 register at
worker start, see `secator health`).

| Area | Tool | Python | Rust | State | Notes |
|---|---|:-:|:-:|---|---|
| Subdomain | subfinder | ✅ | ✅ | Complete | |
| Subdomain | gau | ✅ | ✅ | Complete | also used by url_crawl |
| Subdomain | dnsx | ✅ | ✅ | Complete | `dnsx/brute`, `dnsx/probe` aliases |
| Subdomain | xurlfind3r | ✅ | ✅ | Complete | passive-only |
| Subdomain | urlfinder | ✅ | ✅ | Complete | passive-only |
| HTTP probe | httpx | ✅ | ✅ | Complete | aliases: `tls`, `probe` |
| HTTP probe | wafw00f | ✅ | ✅ | Complete | |
| Crawl | katana | ✅ | ✅ | Complete | |
| Crawl | gospider | ✅ | ✅ | Complete | |
| Crawl | cariddi | ✅ | ✅ | Complete | juicy_extensions / secrets |
| Param hunt | gf | ✅ | ✅ | Complete | xss/lfi/ssrf/rce/idor/interestingparams/debug_logic patterns |
| Param hunt | arjun | ✅ | ✅ | Complete | |
| Param hunt | x8 | ✅ | ✅ | Complete | |
| Bruteforce | ffuf | ✅ | ✅ | Complete | host/url/dir variants |
| Bruteforce | feroxbuster | ✅ | ✅ | Complete | |
| Bruteforce | dirsearch | ✅ | ✅ | Complete | |
| Port scan | nmap | ✅ | ✅ | Complete | XML + NSE vulscan/vulners parsed |
| Port scan | naabu | ✅ | ✅ | Complete | |
| Network | fping | ✅ | ✅ | Complete | |
| Network | arp | ✅ | ✅ | Complete | requires sudo |
| Network | arpscan | ✅ | ✅ | Complete | requires sudo |
| Network | mapcidr | ✅ | ✅ | Complete | |
| Whois / ASN | whois | ✅ | ✅ | Complete | |
| Whois / ASN | jswhois | ✅ | ✅ | Complete | |
| Whois / ASN | whoisdomain | ✅ | ✅ | Complete | |
| Whois / ASN | getasn | ✅ | ✅ | Complete | |
| SSL/TLS | testssl | ✅ | ✅ | Complete | |
| SSL/TLS | sshaudit | ✅ | ✅ | Complete | |
| Vuln scan | nuclei | ✅ | ✅ | Complete | |
| Vuln scan | dalfox | ✅ | ✅ | Complete | XSS, ansi decoder |
| Vuln scan | grype | ✅ | ✅ | Complete | |
| Vuln scan | trivy | ✅ | ✅ | Complete | |
| Vuln scan | bbot | ✅ | ✅ | Complete | |
| Vuln scan | wpprobe | ✅ | ✅ | Complete | |
| Vuln scan | wpscan | ✅ | ✅ | Complete | |
| Vuln search | search_vulns | ✅ | ✅ | Complete | |
| Vuln search | searchsploit | ✅ | ✅ | Complete | |
| Exploits | msfconsole | ✅ | ✅ | Complete | exit-code tolerant |
| Exploits | ph | ✅ | ✅ | Complete | proxy hunter |
| Exploits | bup | ✅ | ✅ | Complete | brute-up |
| Secrets | gitleaks | ✅ | ✅ | Complete | |
| Secrets | trufflehog | ✅ | ✅ | Complete | |
| OSINT | h8mail | ✅ | ✅ | Complete | |
| OSINT | maigret | ✅ | ✅ | Complete | |
| Native | ai | ✅ (Python module) | ✅ (NativeSpec) | Complete | agent loop in Rust, see §AI agent |
| Native | prompt | ✅ | ✅ | Complete | timeout now honors `runners.prompt_timeout` |
| Native | netdetect | ✅ | ✅ | Complete | interface enum via `if-addrs` |
| Native | urlparser | ✅ | ✅ | Complete | |

**Per-tool features**: install pipeline (github-release / source / os-package), auto-install on missing binary, `secator health` check, encoding override (utf-8/ansi), `ignore_return_code`, `requires_sudo`, proxy capabilities (`proxychains`/`proxy_http`/`proxy_socks5`), `kill_on_drop` subprocess teardown — all parity ✅ on both sides.

---

## 2. Workflow, scan, and profile templates

| Type | Name | Python | Rust | State | Notes |
|---|---|:-:|:-:|---|---|
| Workflow | cidr_recon | ✅ | ✅ | Complete | |
| Workflow | code_scan | ✅ | ✅ | Complete | |
| Workflow | domain_recon | ✅ | ✅ | Complete | |
| Workflow | host_recon | ✅ | ✅ | Complete | MVP target |
| Workflow | subdomain_recon | ✅ | ✅ | Complete | |
| Workflow | url_bypass | ✅ | ✅ | Complete | |
| Workflow | url_crawl | ✅ | ✅ | Complete | |
| Workflow | url_dirsearch | ✅ | ✅ | Complete | |
| Workflow | url_fuzz | ✅ | ✅ | Complete | |
| Workflow | url_params_fuzz | ✅ | ✅ | Complete | |
| Workflow | url_secrets_hunt | ✅ | ✅ | Complete | |
| Workflow | url_vuln | ✅ | ✅ | Complete | gf + dalfox |
| Workflow | user_hunt | ✅ | ✅ | Complete | |
| Workflow | wordpress | ✅ | ✅ | Complete | |
| Scan | domain | ✅ | ✅ | Complete | |
| Scan | host | ✅ | ✅ | Complete | |
| Scan | network | ✅ | ✅ | Complete | |
| Scan | subdomain | ✅ | ✅ | Complete | |
| Scan | url | ✅ | ✅ | Complete | |
| Profile | active | ✅ | ✅ | Complete | |
| Profile | aggressive | ✅ | ✅ | Complete | |
| Profile | all_ports | ✅ | ✅ | Complete | |
| Profile | full | ✅ | ✅ | Complete | |
| Profile | http_headless | ✅ | ✅ | Complete | |
| Profile | http_record | ✅ | ✅ | Complete | |
| Profile | hunt_secrets | ✅ | ✅ | Complete | |
| Profile | insane | ✅ | ✅ | Complete | |
| Profile | paranoid | ✅ | ✅ | Complete | |
| Profile | passive | ✅ | ✅ | Complete | |
| Profile | polite | ✅ | ✅ | Complete | |
| Profile | sneaky | ✅ | ✅ | Complete | |
| Profile | stealth | ✅ | ✅ | Complete | |
| Profile | tor | ✅ | ✅ | Complete | |

---

## 3. Engine: composition, dataflow, lifecycle

| Feature | Python | Rust | State | Notes |
|---|:-:|:-:|---|---|
| Chain composition (`tasks:` list) | ✅ | ✅ | Complete | |
| Group composition (`_group/`) | ✅ | ✅ | Complete | True parallel via `futures::future::join_all` (since recent sprint) |
| Conditional gating (`if:`) | ✅ | ✅ | Complete | re-eval at exec time against merged opts |
| Target extractors (`targets_:`) | ✅ | ✅ | Complete | type/field/condition/group_by |
| Opt extractors (`<opt>_:`) | ✅ | ✅ | Complete | |
| Workflow → workflow nesting | ✅ | ✅ | Complete | |
| Scan → workflow nesting | ✅ | ✅ | Complete | per-workflow `targets_:` filter |
| Pruning by `if:` + empty inputs | ✅ | ✅ | Complete | |
| SKIPPED state emission on skip | ✅ | ✅ | Complete | Info + State{SKIPPED} on each early-return path — #151 |
| Chunking (`input_chunk_size`) | ✅ | ✅ | Complete | config fallback when spec sets 0 |
| File-mode `Unsupported` ⇒ 1-per-chunk | ✅ | ✅ | Complete | |
| `chunk_rate_limit` split | ✅ | ✅ | Complete | divides `rate_limit` across chunks |
| Mark duplicates (`mark_duplicates`) | ✅ | ✅ | Complete | |
| Drop duplicates from report (`remove_duplicates`) | ✅ | ✅ | Complete | `Report::build_dedupe(dedupe)` |
| Dedup source preference (Url→httpx, Port→nmap) | ✅ | ✅ | Complete | |
| Validators (`validate_input`) | ✅ | ✅ | Complete | |
| Hooks: `on_init` | ✅ | ✅ | Complete | |
| Hooks: `on_start`, `on_end` | ✅ | ✅ | Complete | |
| Hooks: `on_cmd`, `on_cmd_done` | ✅ | ✅ | Complete | |
| Hooks: `on_line` | ✅ | ✅ | Complete | |
| Hooks: `on_item` (mutate / drop) | ✅ | ✅ | Complete | |
| Hooks: `on_duplicate` | ✅ | ✅ | Complete | |
| Hooks: `on_interval` | ✅ | ✅ | Complete | env-tunable cadence |
| Per-task `output_map` | ✅ | ✅ | Complete | |
| Discriminator (multi-output) | ✅ | ✅ | Complete | |
| Serializers (JSON / regex) | ✅ | ✅ | Complete | dataclass serializer ➖ N/A in Rust (typed model) |
| Stat sampler (`stat_update_frequency`) | ✅ | ✅ | Complete | sysinfo tree walker; AbortOnDrop guard for early cancel |

---

## 4. Output / finding types

13 finding + 6 execution + 1 stat type — 1:1 parity.

| Group | Type | Python | Rust | State |
|---|---|:-:|:-:|---|
| Finding | subdomain | ✅ | ✅ | Complete |
| Finding | ip | ✅ | ✅ | Complete |
| Finding | port | ✅ | ✅ | Complete |
| Finding | url | ✅ | ✅ | Complete |
| Finding | tag | ✅ | ✅ | Complete |
| Finding | exploit | ✅ | ✅ | Complete |
| Finding | user_account | ✅ | ✅ | Complete |
| Finding | vulnerability | ✅ | ✅ | Complete |
| Finding | certificate | ✅ | ✅ | Complete |
| Finding | record | ✅ | ✅ | Complete |
| Finding | domain | ✅ | ✅ | Complete |
| Finding | ai | ✅ | ✅ | Complete |
| Finding | technology | ✅ | ✅ | Complete |
| Execution | target | ✅ | ✅ | Complete |
| Execution | progress | ✅ | ✅ | Complete |
| Execution | info | ✅ | ✅ | Complete |
| Execution | warning | ✅ | ✅ | Complete |
| Execution | error | ✅ | ✅ | Complete |
| Execution | state | ✅ | ✅ | Complete |
| Stat | stat | ✅ | ✅ | Complete |

---

## 5. Exporters

| Exporter | Python | Rust | State | Notes |
|---|:-:|:-:|---|---|
| json | ✅ | ✅ | Complete | |
| csv | ✅ | ✅ | Complete | per-type files |
| txt | ✅ | ✅ | Complete | per-type files |
| markdown | ✅ | ✅ | Complete | |
| table | ✅ | ✅ | Complete | |
| gdrive | ✅ | ✅ | Complete | uses `gcloud` shell-out |
| console | ✅ | ✅ | Complete | `ConsoleExporter` (`-o console`) streams primary fields to stdout — #176 T7 |
| jsonl | ✅ | ✅ | Complete | `JsonlExporter` (`-o jsonl`) writes `report.jsonl` next to `report.json` — #176 T7 |

---

## 6. Drivers (lifecycle / persistence hooks)

| Driver | Python | Rust | State | Notes |
|---|:-:|:-:|---|---|
| MongoDB | ✅ | ✅ | Complete | `secator-mongo` (631 LoC) — insert/dedup main copy, query backend |
| Cloud API | ✅ | ✅ | Complete | `secator-api` (493 LoC) — runner/finding endpoints, queries |
| GCS (file upload) | ✅ | ✅ | Complete | `secator-gcs` (263 LoC) — rewrites screenshot/response paths to `gs://` |
| Discord notify | ✅ | ✅ | Complete | `secator-notify::discord` |
| Slack notify | ➖ | ✅ | Complete | Rust-only addon (same shape as Discord) |
| SQLite | ✅ | ❌ | Deferred by user | Python `hooks/sqlite.py` + query backend; Rust port intentionally postponed |

**Driver trait surface**: `on_run_start` → `on_finding(item)` → `on_run_end(info, items)` — implemented uniformly across all drivers in both runtimes. Skipped-task records (`State{SKIPPED}`) reach `on_finding` in both as of the latest sprint.

---

## 7. CVE / exploit providers

| Provider | Python | Rust | State | Notes |
|---|:-:|:-:|---|---|
| Circl | ✅ | ✅ | Complete | default |
| Vulners | ✅ | ✅ | Complete | requires API key |
| GHSA | ✅ | ✅ | Complete | |
| ExploitDB | ✅ | ✅ | Complete | provides exploit metadata only |
| Provider chaining (`providers.defaults`) | ✅ | ✅ | Complete | YAML key `providers.defaults: {cve: …, exploit: …}` honored in both |
| `runners.skip_cve_low_confidence` filter | ✅ | ✅ | Complete | applied in nmap vulscan/vulners + search_vulns |
| `runners.skip_cve_search` | ✅ | ✅ | Complete | |
| `runners.skip_exploit_search` | ✅ | ✅ | Complete | |

---

## 8. Query backends

| Backend | Python | Rust | State | Notes |
|---|:-:|:-:|---|---|
| JSON (filesystem) | ✅ | ✅ | Complete | `JsonBackend` in `secator-query` |
| MongoDB | ✅ | ✅ | Complete | `secator-mongo::query::MongoBackend` |
| API | ✅ | ✅ | Complete | `secator-api::query` |
| SQLite | ✅ (recent PR #1163) | ❌ | Deferred by user | parity intentionally postponed |
| MongoDB-style filter expressions | ✅ | ✅ | Complete | `secator-query::expr` |
| Dedup hide / filter in build | ✅ | ✅ | Complete | |

---

## 9. Distributed execution

| Feature | Python | Rust | State | Notes |
|---|:-:|:-:|---|---|
| Local in-process execution | ✅ | ✅ | Complete | `LocalTransport` |
| Worker model | ✅ Celery | ✅ Rust worker | Complete | independent reimpl, same wire format inside the Rust side |
| Filesystem broker | ✅ Kombu | ✅ `FileBroker` | Complete | distinct on-disk layouts (`.exchange` vs `tasks/<uuid>.json`) — see ⚠️ Broker collision in §13 |
| Redis broker / Streams | ✅ Celery+Redis | ✅ `RedisTransport` (consumer groups) | Complete | |
| Live progress to client | ✅ | ✅ | Complete | `tail_results` cursor |
| Revoke / cancel | ✅ | ✅ | Complete | `ControlMsg::Revoke` on the broker control channel |
| `transport.task_max_timeout` enforcement | ✅ Celery | ✅ | Complete | wraps `runner.run` in `tokio::time::timeout`; `kill_on_drop(true)` ensures SIGKILL — #157 |
| `transport.worker_max_tasks_per_child` | ✅ | ✅ | Complete | shared atomic + `self_shutdown` flag — #157 |
| `transport.worker_kill_after_idle_seconds` | ✅ | ✅ | Complete | watchdog task — #157 |
| `transport.worker_kill_after_task` | ✅ | ✅ | Complete | Poll loop signals `self_shutdown` after each `process_unit` when set — #172 T3 |
| `transport.task_memory_limit_mb` | ✅ | ✅ | Complete | `spawn_sampler_with_limit` kills the process tree + emits an `Error` on RSS breach — #171 T2 |
| `transport.worker_prefetch_multiplier` | ✅ | ➖ | Complete | Celery prefork concept; Rust worker uses dedicated poll loops |
| `transport.broker_pool_limit` | ✅ | ➖ | Complete | Celery only |
| `transport.broker_visibility_timeout` | ✅ | ➖ | Complete | Celery / Redis-only knob |
| `transport.task_acks_late` | ✅ | ➖ | Complete | Celery semantic |
| `transport.task_send_sent_event` | ✅ | ➖ | Complete | Celery events |
| `transport.task_reject_on_worker_lost` | ✅ | ➖ | Complete | Celery semantic |
| `transport.worker_send_task_events` | ✅ | ➖ | Complete | Celery |
| `transport.override_default_logging` | ✅ | ➖ | Complete | Celery's logging override |
| `transport.worker_command_verbose` | ✅ | 🟡 | Partial | folded into `cli.show_command_output` + `--verbose` |
| `transport.result_expires` | ✅ | ➖ | Complete | Redis result TTL — irrelevant once the run returns |
| Prometheus metrics endpoint | ❌ | ✅ | Complete | `secator-metrics`, `--metrics-addr` flag (Rust-only) |
| Cron-style scheduler (beat) | ✅ Celery beat | ✅ `secator-beat` | Complete | `~/.secator/schedule.yml`, foreground process |

---

## 10. AI agent

| Sub-feature | Python | Rust | State | Notes |
|---|:-:|:-:|---|---|
| LLM dispatch loop | ✅ | ✅ | Complete | `native/ai/agent.rs` |
| Tool: `run_task` | ✅ | ✅ | Complete | registry lookup + dedicated runtime thread |
| Tool: `run_workflow` | ✅ | ✅ | Complete | compiles plan, drives via `LocalTransport` |
| Tool: `run_shell` | ✅ | ✅ | Complete | sanitized env (strip SECATOR_/ANTHROPIC_/AWS_/... and KEY/SECRET/TOKEN/PASSWORD substrings) |
| Tool: `query_workspace` | ✅ | ✅ | Complete | filesystem backend; Mongo/API backends still N/A here |
| Tool: `add_finding` | ✅ | ✅ | Complete | stamps `_source=ai` |
| Tool: `follow_up` (interactive) | ✅ | ✅ | Complete | TTY → prompt; non-TTY → stop with operator info |
| Tool: `stop` | ✅ | ✅ | Complete | |
| Modes (`chat`/`attack`/`exploit`) | ✅ | ✅ | Complete | `build_tool_schemas(mode, …)` filters allowed_actions before tools reach the LLM — #174 T5 |
| Sub-agent dispatch (`run_task ai`) | ✅ | ✅ | Complete | depth cap = `MAX_SUBAGENT_DEPTH` |
| Session save / resume | ✅ | ✅ | Complete | `~/.secator/<sessions>/` JSON records, interactive picker |
| History pruning to token budget | ✅ | ✅ | Complete | drops oldest non-system messages, truncates huge tool results |
| PII encryption (`encrypt_pii`) | ✅ | ✅ | Complete | reversible mask, default-on |
| `--dangerous` guardrail bypass | ✅ | ✅ | Complete | |
| Permissions DSL (allow/deny/ask) | ✅ | ✅ | Complete | `addons.ai.permissions.{allow,deny,ask}` patterns |
| Multi-provider clients (anthropic/openai/gemini/openrouter/xai) | ✅ | ✅ | Complete | litellm-rust fork pinned (freelabz feat/tool-calls) |
| `addons.ai.*` config fallback (default_model, temperature, api_key, …) | ✅ | ✅ | Complete | #158 |
| Cost / pricing tracking | ✅ | ✅ | Complete | |
| Tool: `run_workflow` parallel `_group` | ✅ | ✅ | Complete | now uses DAG dispatch instead of flattened serial |
| `addons.ai.intent_model` | ✅ | ✅ | Complete | When `--mode` is unset, `classify_intent` calls the cheap model with the bundled `modes/_selection.txt` prompt; defaults to `claude-haiku-4-5` — #173 T4 |

---

## 11. CLI commands & UX

| Command / flag | Python | Rust | State | Notes |
|---|:-:|:-:|---|---|
| `secator task / x / t` | ✅ | ✅ | Complete | |
| `secator workflow / w` | ✅ | ✅ | Complete | |
| `secator scan / s` | ✅ | ✅ | Complete | |
| `secator worker / wk` | ✅ | ✅ | Complete | Rust adds `--metrics-addr`, `--redis <url>` |
| `secator profile / p list/show` | ✅ | ✅ | Complete | |
| `secator workspace / ws` | ✅ | ✅ | Complete | |
| `secator config get/set/list` | ✅ | ✅ | Complete | |
| `secator install` | ✅ | ✅ | Complete | `--force_source` plus config fallback |
| `secator health` | ✅ | ✅ | Complete | |
| `secator cheatsheet / ch` | ✅ | ✅ | Complete | |
| `secator reports / r` | ✅ | ✅ | Complete | browse + open |
| `secator addons list/enable/disable` | ✅ | ✅ | Complete | |
| `secator query / q` | ✅ | ✅ | Complete | MongoDB-style filters; `--driver json/mongo/api` |
| `secator beat` (scheduler) | ✅ | ✅ | Complete | |
| `secator schedule list/add/del` | ✅ | ✅ | Complete | `~/.secator/schedule.yml` |
| `secator vuln / v` (CVE/GHSA/EDB lookup) | ✅ | ✅ | Complete | |
| `secator diff` (compare two runs) | ✅ | ✅ | Complete | |
| `secator alias` (shell aliases) | ✅ | ✅ | Complete | |
| `secator update` | ✅ | ✅ | Complete | |
| `secator utils / u` | ✅ | ✅ | Complete | |
| `--tree` (print pruned tree only) | ✅ | ✅ | Complete | |
| `--dry-run` (print resolved cmds, no spawn) | ✅ | ✅ | Complete | |
| `--yaml` (resolved workflow YAML) | ✅ | ✅ | Complete | |
| `--worker` / `--sync` | ✅ | ✅ | Complete | |
| `-pf <profiles>` (profile stacking) | ✅ | ✅ | Complete | |
| `-ws <workspace>` | ✅ | ✅ | Complete | |
| `--threads/--rate-limit/--timeout/--delay` (propagated) | ✅ | ✅ | Complete | |
| `--header / --proxy / --user-agent` (propagated) | ✅ | ✅ | Complete | |
| `--json / --raw` (stdout shape) | ✅ | ✅ | Complete | |
| `--no-color` | ✅ | ✅ | Complete | |
| `-v / --verbose` (default from `cli.show_command_output`) | ✅ | ✅ | Complete | #156 |
| Tab completion | ✅ (click) | ❌ | Not implemented | clap supports it but no wiring yet |
| Live UI (rich panel) | ✅ | ✅ | Complete | `secator-ui` crate, 518 LoC |
| stdin / pipe / file / comma-list ingestion | ✅ | ✅ | Complete | |
| Run-id resolution (`@<id>`) | ✅ | 🟡 | Partial | path-only resolution; named alias TBC |

---

## 12. Config system

| Field family | Python | Rust | State | Notes |
|---|:-:|:-:|---|---|
| `dirs.*` (data/bin/share/templates/reports/wordlists/cves/payloads/performance/revshells/celery*) | ✅ | ✅ | Complete | `set_default_folders` parity via `Dirs::fill_derived()` |
| `transport.*` (broker_url, result_backend, …) | ✅ (`celery.*`) | ✅ (`transport.*` + `celery:` alias) | Complete | rename with deprecation warning |
| `cli.*` (github_token, record, stdin_timeout, show_http_response_headers, show_command_output, exclude_http_response_headers, date_format) | ✅ | ✅ | Complete | |
| `runners.*` (input_chunk_size, progress/stat/backend_update_frequency, poll_frequency, skip_cve_search, skip_exploit_search, skip_cve_low_confidence, remove_duplicates, threads, prompt_timeout, chunk_rate_limit) | ✅ | ✅ | Complete | `poll_frequency` *parsed*, not honored — Rust polls at 50 ms regardless |
| `http.*` (socks5_proxy, http_proxy, store_responses, response_max_size_bytes, proxychains_command, freeproxy_timeout, default_header) | ✅ | ✅ | Complete | every knob wired — `--proxy random` uses `freeproxy::random_proxy` (#175 T6) |
| `tasks.exporters`, `tasks.overrides.<task>.<opt>` | ✅ | ✅ | Complete | overrides applied at runtime (CLI/YAML wins) |
| `workflows.exporters`, `scans.exporters` | ✅ | ✅ | Complete | |
| `payloads.templates` | ✅ | ✅ | Complete | |
| `wordlists.defaults / templates / lists` | ✅ | ✅ | Complete | |
| `profiles.defaults` | ✅ | ✅ | Complete | |
| `drivers.defaults` | ✅ | ✅ | Complete | |
| `workspace.default` | ✅ | ✅ | Complete | |
| `security.allow_local_file_access` | ✅ | ✅ | Complete | |
| `security.auto_install_commands` | ✅ | ✅ | Complete | |
| `security.force_source_install` | ✅ | ✅ | Complete | fallback for both install paths — #155 |
| `security.prompt_sudo_password` | ✅ | ✅ | Complete | rpassword-driven prompt with `requires_sudo` tasks |
| `providers.defaults.{cve,ghsa,exploit}` | ✅ | ✅ | Complete | |
| `offline_mode` | ✅ | ✅ | Complete | short-circuits provider chains |
| `debug` (top-level channel filter) | ✅ (env mainly) | ✅ | Complete | `secator_debug::init(config.debug)` seeded at startup — #156 |
| `addons.gdrive.*` | ✅ | ✅ | Complete | |
| `addons.gcs.*` | ✅ | ✅ | Complete | renamed `credentials_file` → `credentials_path` |
| `addons.worker.*` | ✅ | ✅ | Complete | |
| `addons.mongodb.*` | ✅ | ✅ | Complete | |
| `addons.vulners.*` | ✅ | ✅ | Complete | |
| `addons.ai.*` (api_key, api_base, default_model, intent_model, temperature, max_tokens, max_tokens_total, max_results, user_response_timeout, encrypt_pii, permissions) | ✅ | ✅ | Complete | fallback wired in `native/ai/mod.rs::run` — #158 |
| `addons.discord.*` | ✅ | ✅ | Complete | |
| `addons.api.*` | ✅ | ✅ | Complete | cloud API client |
| `addons.slack.*` | ➖ | ✅ | Complete | Rust-only |
| `SECATOR_<DOTTED>` env overrides | ✅ | ✅ | Complete | recursive keymap, type-coerced |
| YAML round-trip (Python config → Rust binary works unedited) | ➖ | ✅ | Complete | tested via `python_config_yaml_round_trip` regression |

---

## 13. Dynamic discovery & user extensions

| Feature | Python | Rust | State | Notes |
|---|:-:|:-:|---|---|
| Dynamic templates from `~/.secator/templates/*.yaml` (workflows/scans/profiles) | ✅ | ✅ | Complete | `init_user_templates` walks `<dirs.templates>` at startup; user YAML wins over built-ins with a `[WRN]` shadow notice — #161 |
| User-supplied task modules (`.rs` crates in `~/.secator/templates/`) | ✅ (`.py`) | ✅ (`.rs` cdylib) | Complete | `secator template build` compiles via `cargo build --release`; loader dlopens via `libloading` and calls `secator_plugin_v1_register` — #162 |
| External drivers from filesystem | ✅ (`hooks.py`) | ✅ (`.rs` cdylib) | Complete | same plugin entry-point registers via `PluginRegistry::register_driver` — #162 |
| External exporters from filesystem | ✅ | ✅ (`.rs` cdylib) | Complete | same plugin path; `register_exporter` — #162 |
| `custom_templates:` in `~/.secator/config.yml` (git-cloned template packs) | ➖ | ✅ | Complete — Rust-only | Python has no equivalent. A repo listed under `custom_templates:` can ship any mix of Rust task crates, workflow YAMLs, and scan YAMLs; managed via `secator template {sync,add,remove,ls}`. Rebuild is skipped when the git ref is unchanged. Optional `secator.yml` at the repo root declares what the pack exposes; without it, `Cargo.toml` / `workflows/*.yml` / `scans/*.yml` are auto-detected. |
| Tool overrides via `tasks.overrides.<task>.<opt>` (config-only, no plugin) | ✅ | ✅ | Complete | works for any registered task — #155 |

**Impact note (historical)**: through the sprint of 2026-06-13, the Rust binary now honors `~/.secator/templates/` — YAML workflows / scans / profiles are picked up at startup and `.rs` plugin crates compiled by `secator template build` register their tasks/drivers/exporters via the `secator-plugin-api` ABI (entry point: `secator_plugin_v1_register`, ABI version probe: `secator_plugin_v1_abi_version`). Plugins MUST be built with the same `rustc` + `secator-plugin-api` revision as the host — the loader emits a clear error on ABI-version mismatch and silently skips dylibs with the wrong symbol set.

---

## 14. Niche / corner-case knobs

| Knob | Python | Rust | State | Notes |
|---|:-:|:-:|---|---|
| Worker concurrency (`-c`) | ✅ | ✅ | Complete | |
| Worker queue filter (`-Q`) | ✅ | ➖ | Complete | Rust workers consume from a single `tasks/` dir; no per-queue routing |
| `--reload` (watchmedo auto-restart) | ✅ | ❌ | Not implemented | Rust workers don't reload on source change (compiled binary) |
| `--check` worker | ✅ | ❌ | Not implemented | |
| `--dev` worker (verbose Celery) | ✅ | ➖ | Complete | Celery-specific |
| `worker_kill_after_task` (kill after each task) | ✅ | ✅ | Complete | Poll loop signals `self_shutdown` after each task — #172 T3 |
| `worker_kill_after_idle_seconds` | ✅ | ✅ | Complete | watchdog — #157 |
| `worker_max_tasks_per_child` | ✅ | ✅ | Complete | #157 |
| Sudo password prompt + cache | ✅ | ✅ | Complete | `rpassword` interactive |
| Proxychains prefix on commands | ✅ | ✅ | Complete | configurable command name |
| `--proxy random` (FreeProxy library) | ✅ | ✅ | Complete | `freeproxy::random_proxy` fetches from proxyscrape, probes up to 8, returns first live `http://ip:port`; honors `http.freeproxy_timeout` — #175 T6 |
| `--proxy auto / socks5 / http / proxychains` | ✅ | ✅ | Complete | |
| Output-encoding switch (utf-8 / ansi) | ✅ | ✅ | Complete | |
| `ignore_return_code` per task | ✅ | ✅ | Complete | declared on spec; Rust runner doesn't gate on exit either way |
| Stat tree walking (cpu/mem per descendant) | ✅ | ✅ | Complete | sysinfo tree walk |
| Per-process memory limit kill | ✅ | ✅ | Complete | sampler enforces `transport.task_memory_limit_mb` via process-tree RSS check; emits `Error` + kills root — #171 T2 |
| SIGKILL on task timeout | ✅ | ✅ | Complete | `kill_on_drop(true)` on `TokioCommand` — #157 |
| AbortOnDrop guards (sampler / hooks) | ➖ | ✅ | Complete | needed because cancel-on-drop can leak otherwise |
| Run-folder allocation (`<reports>/<ws>/<kind>s/<id>/`) | ✅ | ✅ | Complete | next-id picker; `.inputs/` + `.outputs/` |
| `.outputs/index.txt` for stored httpx responses | ✅ | ✅ | Complete | |
| Isolated run-output dir per task | ✅ (recent: PR #1081) | ✅ | Complete | |
| Tree prune empty branches before show | ✅ (PR #1077) | ✅ | Complete | |
| Multi-target dedup in worker mode (PR #1085) | ✅ | ✅ | Complete | |
| `recordings.write` (asciinema or similar) | ✅ | ❌ | Not implemented | Python `cli.record` flag drives `asciinema rec` wrapping |
| Tab-completion install (`secator alias`) | ✅ | 🟡 | Partial | aliases generated; clap-completion not yet wired |
| Cheatsheet markdown generation | ✅ | ✅ | Complete | |

---

## 15. Backend integrations

| Integration | Python | Rust | State | Notes |
|---|:-:|:-:|---|---|
| Celery broker (Redis/filesystem) | ✅ | ➖ | Complete | replaced by Rust-native FileBroker + Redis Streams transport |
| Airflow 3.0+ DAG generation | ✅ | ❌ | Deferred by user | Python-only, lives in `secator/airflow/` — Rust port intentionally postponed |
| Secator Cloud API client | ✅ | ✅ | Complete | `secator-api` crate, endpoints + queries |
| Helm chart for k8s | ✅ | ➖ | Complete | runtime-agnostic, applies to either |
| Docker images | ✅ | ✅ | Complete | `rust/Dockerfile` (2-stage: rust:1.83-bookworm → debian:bookworm-slim, `flavor=full\|lite`, `build_from_source=true\|false`) + `rust/Dockerfile.dev` for bind-mount iteration — #160 |
| Cloud Build / CI pipelines | ✅ | ❌ | Not implemented | release automation pending |

---

## 16. Test surface

| Test type | Python | Rust | State |
|---|:-:|:-:|---|
| Unit (per task / model / config) | ✅ pytest | ✅ cargo test (50+ binaries, 426+ assertions) | Complete |
| Integration (per workflow / scan against fixtures) | ✅ | 🟡 partial — workflow/scan smoke tests via fake brokers | Partial |
| Lint / format | flake8 | clippy / rustfmt | Complete |
| End-to-end against live target | manual | manual (worker mode demo green) | Complete |

---

## 17. Summary

**Total parity**: roughly **92%** by feature surface area, **>99%** of the everyday operator-facing paths (tool runs, workflow composition, scan reports, profiles, drivers, providers, query, AI agent, CLI commands).

**State rollup** (across all tables above, excluding the per-tool / per-template tables which are uniformly Complete):

- **Complete** — the overwhelming majority of cells; after the T1–T8 sprint this now covers all per-mode `allowed_actions` enforcement, `addons.ai.intent_model`, `--proxy random` (FreeProxy-equivalent), `console`/`jsonl` exporters, `transport.task_memory_limit_mb` kill-path, `transport.worker_kill_after_task`, and `secator template scaffold`.
- **Partial** — `transport.worker_command_verbose`, tab-completion install, run-id resolution, integration test surface.
- **Not implemented** — worker `--reload` / `--check`, asciinema recording, tab completion install, Cloud Build pipelines.
- **Deferred by user** — SQLite driver (§6), SQLite query backend (§8), Airflow 3.0+ DAG generation (§15).
- **Intentionally not ported** (Python-shaped problems that don't exist in Rust; see §18):
  - `ADDONS_ENABLED` PyPI-extras probe / `secator utils enable-addon` — Python runtime-gates optional deps (gevent, pymongo, litellm, …); Rust cdylibs are already gated at compile time. Replaced by `custom_templates:` for the third-party-plugin distribution use case.

**Rust-only extensions** (Python doesn't have these):
- Prometheus metrics endpoint (`--metrics-addr`)
- Slack notifier addon (mirror of Discord)
- Worker self-shutdown watchdog (`worker_kill_after_idle_seconds` actually fires; Python relies on Celery beat)
- `AbortOnDrop` cancellation guards (needed in async Rust; N/A in Python)
- `custom_templates:` — git-cloned third-party template packs (tasks/workflows/scans); `secator template {sync,add,remove,ls}` manages the list, skip-if-unchanged on rebuild
- `kill_on_drop` on subprocess (parity with Celery's `task_max_timeout` enforcement)
- True parallel `_group` execution via `futures::future::join_all` (Python's Celery does this via `group(...)`; Rust matched it).

---

## 18. Intentionally not ported

This section lists Python features the Rust port deliberately does **not**
implement, along with the reasoning. Future parity audits should treat these as
**Complete-by-omission**, not as gaps.

### 18.1 `ADDONS_ENABLED` PyPI-extras probe

**Python behaviour.** `secator/__init__.py` inspects `sys.modules` / imports at
startup to detect which extras (`worker`, `google`, `mongo`, `ai`, `redis`,
`api`, `slack`, `discord`, `dev`, `trace`, `build`) are installed. `secator
utils enable-addon <name>` flips a config flag AND runs `pip install
'secator[<name>]'` to bring optional dependencies in. `disable-addon` mutates
the same flag; the extra stays installed. The pattern exists because Python
extras are runtime-detected — an operator can install `secator` bare, then add
`secator[ai]` later without rebuilding anything, and the CLI must gracefully
degrade when the underlying import isn't available.

**Rust equivalent (why it's a non-problem).** Rust has no runtime dependency
resolution. A cdylib either compiled with its deps or it didn't. There's
nothing to "enable at runtime" — the compile step is the gate. Concretely:

| Python addon | Rust equivalent | State |
|---|---|---|
| `secator[worker]` (gevent, celery) | Built into `secator-worker` unconditionally (tokio-based, not celery) | Complete |
| `secator[google]` (Google Drive API) | Built into `secator-gcs` unconditionally | Complete |
| `secator[mongo]` (pymongo) | Built into `secator-mongo` unconditionally | Complete |
| `secator[ai]` (litellm) | Built into the AI runner unconditionally (via FreeLabz `litellm-rust`) | Complete |
| `secator[redis]` | Built into `secator-redis` unconditionally | Complete |
| `secator[api]` (fastapi client) | Built into `secator-api` unconditionally | Complete |
| `secator[slack]` / `secator[discord]` | Built into `secator-notify` unconditionally | Complete |
| `secator[trace]` (memray) | Not applicable (Rust has different profilers) | N/A |
| `secator[dev]` / `secator[build]` | `cargo` handles this via `--features` at build time | N/A |

Runtime enable/disable is still available for the per-addon toggles: `addons.<name>.enabled`
in `~/.secator/config.yml` (Mongo, GCS, AI, API, Slack, Discord, Vulners). Those flags gate
whether the driver is *wired in*, not whether the *code is present*. Managed via
`secator addons {enable,disable,list}`.

**Third-party distribution.** The one legitimate use case Python's `ADDONS_ENABLED`
covered that Rust needs a replacement for — "how does someone else distribute
a plugin so operators can install it after the fact" — is answered by
[`custom_templates:`](#13-external-configs--drop-ins), a git-URL list managed
via `secator template {sync,add,remove,ls}`. It's a superset: a pack can ship
Rust task crates AND workflow/scan YAMLs in the same repo.

**Auditor's rule of thumb.** If you're reviewing this codebase and see a
Python code path with `ADDONS_ENABLED`, `enable_addon`, `disable_addon`, or
per-extra `try: import x except ImportError`, do NOT add a parity row for it
— the Rust equivalent is compile-time, not runtime, and there is nothing to
port.
