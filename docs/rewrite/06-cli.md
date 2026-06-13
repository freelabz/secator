# CLI

Secator's CLI is built with **rich-click** (Click + Rich rendering). The distinctive
feature is that task/workflow/scan subcommands and their options are **generated
dynamically** from task classes and YAML templates at startup. Source: `secator/cli.py`
(entry), `secator/cli_helper.py` (dynamic command generation), `secator/click.py`
(custom Click group + list param type), `secator/decorators.py`.

Entry point: `secator = 'secator.cli:cli'` (pyproject scripts).

---

## 1. Command surface

Top-level group `cli` (with `--version`, `--quiet`). Subgroups/commands (with aliases):

| Command | Aliases | Purpose |
|---|---|---|
| `task` | `x`, `t`, `tasks` | Run a single task. Each task class → a generated subcommand. |
| `workflow` | `w`, `workflows` | Run a workflow. Each workflow YAML → a generated subcommand. |
| `scan` | `s`, `scans` | Run a scan. Each scan YAML → a generated subcommand. |
| `worker` | `wk` | Start a Celery worker (concurrency, queue, pool=gevent, reload, dev/multi). |
| `util` | `u` | proxy, revshell, serve (HTTP), completion, record (VHS), gif, build, publish. |
| `config` | `c` | get/set/unset/edit/default. |
| `workspace` | `ws`, `workspaces` | list/use/create/current/rm. |
| `profile` | `p`, `profiles` | list. |
| `alias` | `a`, `aliases` | enable/disable/list shell aliases for tasks/workflows. |
| `report` | `r`, `reports` | show/list/delete stored reports (with query + format). |
| `health` | `h` | check installed tools and versions. |
| `cheatsheet` | `cs` | command reference. |
| `install` | `i` | install tools / addons / langs. |
| `update` | | self-update. |
| `test` | | unit/integration/lint/etc (dev). |

So `secator x nmap <target>`, `secator w host_recon <target>`, `secator s host <target>`.

---

## 2. Dynamic command generation (`register_runner`)

For each task/workflow/scan, `register_runner(endpoint, config)`:
1. Picks the runner class (`Task`/`Workflow`/`Scan`) and computes `input_types`,
   `short_help` (task help shows category + docstring).
2. Calls `get_config_options(config, exec_opts=CLI_EXEC_OPTS, output_opts=CLI_OUTPUT_OPTS,
   type_mapping=CLI_TYPE_MAPPING)` to flatten all options (see `05-config-templates.md`).
3. Defines a Click command `func(ctx, **opts)` decorated with:
   - `@click.argument('inputs', metavar=<input types>)` — the target(s).
   - `@decorate_command_options(options)` — adds one `click.option` per resolved option.
   - `@click.pass_context`.
4. Registers Rich help **option groups** (`generate_rich_click_opt_groups`) so options are
   visually grouped by prefix (Targets, Execution, Output, Meta, Config, Shared task,
   Task/Workflow/Scan), sorted by a fixed order.

### Global option sets
- `CLI_OUTPUT_OPTS`: `output` (`-o`, exporters), `fmt`, `json`, `raw`, `stat`, `quiet`
  (`/verbose`), `yaml`, `tree`, `dry_run`, `process` (`/no-process`), `version`.
- `CLI_EXEC_OPTS`: `workspace` (`-ws`), `profiles` (`-pf`), `driver`, `sync` (`/worker`),
  `no_poll`, `enable_pyinstrument`, `enable_memray`.
- `CLI_TYPE_MAPPING`: `str→str`, `list→CLICK_LIST` (comma-split param type), `int`, `float`.

### `decorate_command_options`
Translates each resolved option into a `click.option`:
- long flag `--opt`, short `-<short>` (deduplicated: first claimant — i.e. global opts —
  keeps the short form when collisions occur).
- `reverse` boolean defaults → `--opt/--no-opt` (or `--opt/--opposite`).
- `applies_to`, `default_from`, `choices` annotations appended to help.
- `internal_name` → stored under an alternate dest name.

---

## 3. Request handling (the generated `func`)

1. Handle `--version` (task only), `--yaml` (print config), `--tree` (print pruned tree)
   — each exits early.
2. `expand_input(inputs, ctx)` — resolve targets: stdin (piped), a file path (read lines,
   unless input type is `path`), a comma-list, or a single value. Shows help if no input
   and input is required.
3. Resolve **drivers** (`--driver`): validate against `AVAILABLE_DRIVERS`, check addon
   availability, import each `secator.hooks.<driver>.HOOKS`, merge them.
4. Decide **sync vs async**: `--sync`/`--dry-run` force sync; otherwise check if a Celery
   worker is alive (`is_celery_worker_alive`) — alive → async (remote), else sync (local).
   Redis-broker configs require the `redis` addon.
5. Optionally start a profiler (pyinstrument/memray).
6. Set print options (`print_cmd/item/line/start/target/end`, `print_remote_info` when
   async, piped flags) and build the runner: `runner = runner_cls(config, inputs,
   run_opts=opts, hooks=hooks, context=context)`.
7. Iterate `for item in runner:` — this drives execution and live output.

`expand_input` and the stdin/piped handling matter for a rewrite: Secator is built to be
piped (`secator x subfinder example.com | secator x httpx`).

---

## 4. Custom Click pieces (`click.py`)

- `OrderedGroup(RichGroup)` — preserves command order, supports `aliases=[...]` on groups
  and commands (hidden alias commands sharing params/help).
- `ListParamType` (`CLICK_LIST`) — converts comma-separated CLI strings to lists.

---

## 5. Notable utility commands

- `secator worker` — builds and execs a `celery worker` (or `celery multi` in dev mode),
  pool defaults to `gevent`, supports `--reload` (watchdog), `--queue`, `--check`.
- `secator install tools|addons|langs` — drives `installer.py` (`08-subsystems.md` §6).
- `secator health` — per-tool version/status table.
- `secator report show <query>` — reads stored reports through the `QueryEngine`,
  supports `--query` (Python-ish or MongoDB JSON), `--format`, `--time-delta`,
  `--workspace`, `--driver`, `--dedupe`.
- `secator alias enable` — generates shell aliases so tasks/workflows can be invoked
  directly.

---

## 6. Rewrite implications

- The dynamic CLI is elegant but Python/Click-specific. In Go/Rust, generate
  subcommands at startup from the (registered) task list and the (parsed) templates —
  e.g. with cobra/clap dynamic command registration. The hard part is **reproducing
  `get_config_options`** (option flattening + conflict disambiguation + help grouping),
  not the Click wiring.
- Preserve: stdin/pipe ingestion, comma-list expansion, file-of-targets expansion,
  `--sync/--worker` auto-detection, `--tree`/`--yaml`/`--dry-run` introspection, and the
  driver→hooks wiring.
