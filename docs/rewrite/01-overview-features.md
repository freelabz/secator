# Overview & Features

## What Secator is

Secator ("the pentester's swiss knife") is a **task and workflow runner for security
assessments**. It wraps ~50 well-known security tools (nmap, httpx, nuclei, subfinder,
ffuf, gitleaks, …) behind a unified CLI/library, normalizes their wildly different
inputs and outputs into one schema, and lets you compose them into workflows and scans
that can run locally or distributed across workers.

- Language: Python (≥3.8). ~29k LOC.
- License: BSL 1.1 (free for non-commercial use).
- Package: `secator` (PyPI); entry point `secator`.
- Vendor: FreeLabz; there is also a cloud product (`secator.cloud`) the `api` driver
  talks to.

## The core value propositions (from the README, validated in code)

1. **Curated list of commands** — a hand-picked set of tools integrated to a quality bar.
2. **Unified input options** — `--header`, `--rate-limit`, `--proxy`, `--threads`, etc.
   mean the same thing across tools; targets are auto-detected (URL/IP/host/CIDR/…).
3. **Unified output schema** — every tool's output becomes typed records (Url, Port,
   Vulnerability, Subdomain, …) that dedupe, sort, export, and stream consistently.
4. **CLI and library usage** — the same runner objects power the CLI and can be imported.
5. **Distributed execution with Celery** — the same workflow runs in-process or fanned
   out to workers; live progress streams back.
6. **Composition from simple tasks to complex workflows/scans** — YAML DSL with
   conditions and dynamic result-to-input wiring.
7. **Customizable** — tasks, workflows, scans, profiles, drivers, exporters are all
   pluggable; per-task config overrides; external tasks/templates from a user directory.

## The conceptual model

```
Task      = one tool run (nmap, httpx, …), produces typed findings
Workflow  = an ordered DAG of tasks (parallel groups + sequential chains),
            with conditions and dynamic target/option wiring
Scan      = an ordered chain of workflows
Profile   = a named bundle of option presets (aggressive, stealth, tor, …)
Driver    = a bundle of lifecycle hooks (mongodb, api, discord, gcs) for persistence/notify
Exporter  = a report formatter (json, csv, txt, markdown, table, gdrive, console)
Provider  = a CVE/exploit data source (circl, vulners, ghsa, exploitdb)
Workspace = a named grouping of reports (a folder / a DB partition)
```

Everything that executes is a `Runner` (`02-architecture.md`). Everything a tool emits is
an `OutputType` (`03-data-model.md`).

## Usage shapes

```bash
secator x nmap 10.0.0.0/24            # run a task
secator w host_recon example.com      # run a workflow
secator s host example.com            # run a scan
secator x subfinder example.com | secator x httpx   # piping (raw stdout)
secator x httpx example.com -o json,csv             # choose exporters
secator w host_recon example.com -pf aggressive     # apply a profile
secator w host_recon example.com --worker           # force distributed
secator x nmap example.com --tree                   # introspect the plan
secator report show vulnerability --query 'severity == "high"'
secator health                                      # tool versions
secator install tools nmap                          # auto-install a tool
```

## Headline features that shape any rewrite

- **Unified, deduplicating, streamable output schema** (the heart of the product).
- **Declarative tool integration** (option schema + parsing config + hooks).
- **YAML workflow/scan DSL** with `if:` conditions and `<opt>_`/`targets_` extractors
  that flow results from one tool into the next.
- **Profiles** (option presets) and **per-task overrides**.
- **Local/distributed parity** via a chain/group/chord composition model with chunking,
  live progress, and result forwarding.
- **Pluggable drivers** (persistence/notification) as lifecycle hooks; **exporters** as
  report formatters; **providers** for CVE enrichment.
- **Auto-install** of tools from GitHub releases / source / OS packages.
- **An embedded autonomous AI pentest agent** with a guardrail/permission engine.
- **Rich terminal UX** (live panels, trees, tables) — but always pipe-friendly via
  stderr/stdout separation.

## Dependency footprint (mapping targets for a rewrite)

Core Python deps and their roles (so a Go/Rust port knows what to replace):
- `celery` (+ optional `redis`, `gevent`, `flower`) — distributed execution.
- `click` + `rich-click` + `rich` — CLI + terminal UI.
- `pydantic` — config validation. `dotmap` — attribute-dict access. `pyyaml` — templates.
- `validators`, `tldextract`, `dnspython`, `furl` — input detection / parsing.
- `psutil` — process monitoring (CPU/mem, kill). `requests` — HTTP.
- `cpe`, `packaging` — CVE/version logic.
- `xmltodict`, `beautifulsoup4` — tool-output / provider parsing.
- Optional addons: `pymongo` (mongodb), `google-*`/`gspread` (gdrive/gcs), `litellm` +
  `safecmd` (AI), `memray`/`pyinstrument` (profiling).
