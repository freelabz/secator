# Secator Configuration Reference

> **Quick links:** [File Location](#configuration-file-location) · [CLI Commands](#configuration-management) · [Environment Variables](#environment-variable-overrides) · [Full Example](#complete-configuration-example)

Secator's configuration lives in `~/.secator/config.yml`. Every option can also be overridden with a `SECATOR_*` environment variable (see [Environment Variable Overrides](#environment-variable-overrides)).

---

## Table of Contents

| Section | Description |
|---------|-------------|
| [debug](#debug) | Debug output filtering |
| [dirs](#dirs) | Data directory paths |
| [celery](#celery) | Distributed task queue |
| [cli](#cli) | CLI behavior |
| [runners](#runners) | Task runner settings |
| [http](#http) | HTTP / proxy settings |
| [tasks](#tasks) | Task-level settings |
| [workflows](#workflows) | Workflow-level settings |
| [scans](#scans) | Scan-level settings |
| [payloads](#payloads) | Payload templates |
| [wordlists](#wordlists) | Wordlist templates |
| [profiles](#profiles) | Execution profiles |
| [drivers](#drivers) | Execution drivers |
| [workspace](#workspace) | Workspace settings |
| [addons](#addons) | Optional integrations |
| [providers](#providers) | Data providers |
| [security](#security) | Security controls |
| [offline_mode](#offline_mode) | Offline operation |

---

## Configuration File Location

| | |
|-|--|
| **Default path** | `~/.secator/config.yml` |
| **Override via** | `SECATOR_DIRS_DATA` environment variable |

The configuration file is created automatically on first run. You can edit it directly or use the `secator config` commands.

---

## debug

**Type:** `string` · **Default:** `''`

Controls which debug components produce output. Accepts a comma-separated list of component names or patterns.

| Value | Effect |
|-------|--------|
| `''` (empty) | No debug output (default) |
| `all` or `1` | All debug output |
| `celery,hooks` | Only Celery and hook output |
| `cve.*` | All CVE components (regex) |

### Matching Behavior

- **Simple names** (no wildcard) → `sub.startswith(pattern)` — prefix matching
- **Patterns with `*`** → `re.match(pattern + '$', sub)` — regex matching with automatic end-anchor

### Available Components

| Component | Description |
|-----------|-------------|
| `celery` | Celery task execution |
| `celery.app` | Celery application init |
| `celery.data` | Celery data operations |
| `celery.poll` | Celery polling |
| `celery.state` | Celery state management |
| `cli` | CLI operations |
| `config` | Configuration loading |
| `cve` | CVE operations |
| `cve.circl` | CIRCL CVE provider |
| `cve.match` | CVE matching |
| `cve.nmap` | Nmap CVE detection |
| `cve.provider` | CVE provider operations |
| `cve.vulners` | Vulners CVE provider |
| `duplicates` | Duplicate detection |
| `end` | Task completion |
| `error` | Error handling |
| `extractor` | Output extraction |
| `extractors` | Output extractors |
| `hooks` | Hook execution |
| `hooks.gcs` | Google Cloud Storage hooks |
| `hooks.mongodb` | MongoDB hooks |
| `init` | Initialization |
| `init.options` | Option initialization |
| `installer` | Tool installation |
| `item` | Item processing |
| `item.convert` | Item conversion |
| `item.duplicate` | Duplicate detection per item |
| `line.print` | Line printing |
| `line.process` | Line processing |
| `monitor` | Monitoring |
| `run` | Task execution |
| `start` | Task start |
| `stats` | Statistics |
| `template` | Template operations |
| `unittest` | Unit testing |
| `unittest.dict` | Dict unit tests |
| `unittest.item` | Item unit tests |
| `validators` | Validation |

```yaml
# Examples
debug: all                   # everything
debug: celery,hooks          # two components (prefix match)
debug: cve.*                 # regex — cve.match, cve.circl, …
debug: ''                    # disabled (default)
```

---

## dirs

**Type:** `object`

Directory paths used by Secator. All paths support `~` expansion.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `dirs.bin` | `Path` | `~/.local/bin` | Binary executables |
| `dirs.share` | `Path` | `~/.local/share` | Shared data files |
| `dirs.data` | `Path` | `~/.secator` | Root data directory |
| `dirs.templates` | `Path` | `{data}/templates` | Workflow/scan templates |
| `dirs.reports` | `Path` | `{data}/reports` | Generated reports |
| `dirs.wordlists` | `Path` | `{data}/wordlists` | Wordlists |
| `dirs.cves` | `Path` | `{data}/cves` | CVE data |
| `dirs.payloads` | `Path` | `{data}/payloads` | Exploit payloads |
| `dirs.performance` | `Path` | `{data}/performance` | Performance metrics |
| `dirs.revshells` | `Path` | `{data}/revshells` | Reverse shell payloads |
| `dirs.celery` | `Path` | `{data}/celery` | Celery broker files |
| `dirs.celery_data` | `Path` | `{data}/celery/data` | Celery data files |
| `dirs.celery_results` | `Path` | `{data}/celery/results` | Celery result files |

```yaml
dirs:
  data: ~/.secator
  bin: ~/.local/bin
  wordlists: /custom/wordlists
```

---

## celery

**Type:** `object`

Celery distributed task queue settings.

### Broker

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `celery.broker_url` | `string` | `filesystem://` | Broker URL |
| `celery.broker_pool_limit` | `int` | `10` | Max broker connections |
| `celery.broker_connection_timeout` | `float` | `4.0` | Connection timeout (s) |
| `celery.broker_visibility_timeout` | `int` | `3600` | Visibility timeout (s) |
| `celery.broker_transport_options` | `string` | `''` | JSON broker transport options |

**Broker URL examples:**
- `filesystem://` — file system (default)
- `redis://localhost:6379/0` — Redis
- `amqp://guest:guest@localhost:5672//` — RabbitMQ

### Result Backend

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `celery.result_backend` | `string` | `file://{dirs.celery_results}` | Result backend URL |
| `celery.result_backend_transport_options` | `string` | `''` | JSON backend transport options |
| `celery.result_expires` | `int` | `86400` | Result TTL in seconds (1 day) |
| `celery.override_default_logging` | `bool` | `true` | Override Celery logging |

### Task Behavior

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `celery.task_acks_late` | `bool` | `false` | Acknowledge after execution |
| `celery.task_send_sent_event` | `bool` | `false` | Emit task-sent events |
| `celery.task_reject_on_worker_lost` | `bool` | `false` | Reject on worker loss |
| `celery.task_max_timeout` | `int` | `-1` | Max task duration (s); `-1` = unlimited |
| `celery.task_memory_limit_mb` | `int` | `-1` | Max task memory (MB); `-1` = unlimited |

### Worker

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `celery.worker_max_tasks_per_child` | `int` | `20` | Tasks before worker recycle |
| `celery.worker_prefetch_multiplier` | `int` | `1` | Tasks to prefetch per worker |
| `celery.worker_send_task_events` | `bool` | `false` | Workers emit task events |
| `celery.worker_kill_after_task` | `bool` | `false` | Kill worker after each task |
| `celery.worker_kill_after_idle_seconds` | `int` | `-1` | Kill worker after idle (s); `-1` = disabled |
| `celery.worker_command_verbose` | `bool` | `false` | Verbose worker command output |

```yaml
celery:
  broker_url: redis://localhost:6379/0
  result_backend: redis://localhost:6379/1
  worker_max_tasks_per_child: 50
  result_expires: 172800  # 2 days
```

---

## cli

**Type:** `object`

CLI behavior settings.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `cli.github_token` | `string` | `$GITHUB_TOKEN` or `''` | GitHub API token |
| `cli.record` | `bool` | `false` | Record CLI sessions |
| `cli.stdin_timeout` | `int` | `1000` | Stdin timeout (ms) |
| `cli.show_http_response_headers` | `bool` | `false` | Show HTTP response headers |
| `cli.show_command_output` | `bool` | `false` | Show raw command output |
| `cli.exclude_http_response_headers` | `list[str]` | `[connection, content_type, content_length, date, server]` | Headers to hide |
| `cli.date_format` | `string` | `%m/%d/%Y` | Date display format (use `%d/%m/%Y` for European) |

```yaml
cli:
  github_token: ghp_xxxxxxxxxxxxxxxxxxxx
  date_format: "%d/%m/%Y"   # European format
  show_http_response_headers: true
  exclude_http_response_headers: [date, server]
```

---

## runners

**Type:** `object`

Settings that control how tasks, workflows, and scans execute.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `runners.input_chunk_size` | `int` | `100` | Inputs per chunk |
| `runners.progress_update_frequency` | `int` | `20` | Progress update interval (items) |
| `runners.stat_update_frequency` | `int` | `20` | Stats update interval (items) |
| `runners.backend_update_frequency` | `int` | `5` | Backend push interval (s) |
| `runners.poll_frequency` | `int` | `5` | Distributed status poll interval (s) |
| `runners.threads` | `int` | `50` | Default thread count |
| `runners.prompt_timeout` | `int` | `20` | Interactive prompt timeout (s) |
| `runners.chunk_rate_limit` | `bool` | `true` | Rate-limit chunk processing |
| `runners.skip_cve_search` | `bool` | `false` | Skip CVE enrichment |
| `runners.skip_exploit_search` | `bool` | `false` | Skip exploit search |
| `runners.skip_cve_low_confidence` | `bool` | `false` | Skip low-confidence CVEs |
| `runners.remove_duplicates` | `bool` | `false` | Deduplicate results |

```yaml
runners:
  input_chunk_size: 50
  threads: 100
  remove_duplicates: true
  skip_cve_search: false
```

---

## http

**Type:** `object`

HTTP request and proxy settings.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `http.socks5_proxy` | `string` | `socks5://127.0.0.1:9050` | SOCKS5 proxy (Tor) |
| `http.http_proxy` | `string` | `https://127.0.0.1:9080` | HTTP/HTTPS proxy |
| `http.store_responses` | `bool` | `true` | Store HTTP responses to disk |
| `http.response_max_size_bytes` | `int` | `100000` | Max stored response size (~97 KB) |
| `http.proxychains_command` | `string` | `proxychains` | Proxychains binary |
| `http.freeproxy_timeout` | `int` | `1` | Free proxy test timeout (s) |
| `http.default_header` | `string` | `User-Agent: Mozilla/5.0 (Windows NT 10.0…) Chrome/134` | Default HTTP header |

```yaml
http:
  socks5_proxy: socks5://127.0.0.1:9050
  http_proxy: http://proxy.example.com:8080
  store_responses: true
  response_max_size_bytes: 500000
  default_header: "User-Agent: MyCustomAgent/1.0"
```

---

## tasks

**Type:** `object`

Task-level output settings.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `tasks.exporters` | `list[str]` | `[json, csv, txt, markdown]` | Available export formats |
| `tasks.overrides` | `dict` | `{}` | Per-task option overrides |

`tasks.overrides` lets you set default options for specific tasks:

```yaml
tasks:
  exporters: [json, csv]
  overrides:
    nmap:
      rate: 1000
    httpx:
      timeout: 30
```

---

## workflows

**Type:** `object`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `workflows.exporters` | `list[str]` | `[json, csv, txt, markdown]` | Available export formats |

```yaml
workflows:
  exporters: [json, csv]
```

---

## scans

**Type:** `object`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `scans.exporters` | `list[str]` | `[json, csv, txt, markdown]` | Available export formats |

```yaml
scans:
  exporters: [json]
```

---

## payloads

**Type:** `object`

Payload management.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `payloads.templates` | `dict[str, str]` | See below | Name → URL/path mapping |

**Default templates:**

| Name | Source |
|------|--------|
| `lse` | `https://github.com/diego-treitos/linux-smart-enumeration/…/lse.sh` |
| `linpeas` | `https://github.com/carlospolop/PEASS-ng/…/linpeas.sh` |
| `sudo_killer` | `https://github.com/TH3xACE/SUDO_KILLER/…/V3.zip` |

URLs support:
- `https://` — downloaded automatically
- `git+https://` — cloned as a Git repository
- `/absolute/path` or `~/relative` — local file

```yaml
payloads:
  templates:
    custom_payload: https://example.com/payload.sh
    custom_repo: git+https://github.com/user/repo.git
    local_script: /path/to/local/script.sh
```

---

## wordlists

**Type:** `object`

Wordlist management.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `wordlists.defaults` | `dict[str, str]` | `{http: bo0m_fuzz, dns: combined_subdomains, http_params: burp-parameter-names}` | Type → wordlist name |
| `wordlists.templates` | `dict[str, str]` | See below | Name → URL/path |
| `wordlists.lists` | `dict[str, list[str]]` | `{}` | Inline wordlists |

**Default templates:**

| Name | Source |
|------|--------|
| `bo0m_fuzz` | SecLists fuzz.txt |
| `combined_subdomains` | SecLists combined_subdomains.txt |
| `directory_list_small` | directory-list-2.3-small.txt |
| `burp-parameter-names` | SecLists burp-parameter-names.txt |

```yaml
wordlists:
  defaults:
    http: my_custom_wordlist
  templates:
    my_custom_wordlist: https://example.com/wordlist.txt
  lists:
    inline_list: [admin, test, api, login]
```

---

## profiles

**Type:** `object`

Execution profiles that preset task options.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `profiles.defaults` | `list[str]` | `[]` | Profiles applied automatically |

**Built-in profiles** (in `secator/configs/profiles/`):

| Profile | Effect |
|---------|--------|
| `aggressive` | Fast, noisy scans |
| `sneaky` | Slow, stealthy scans |
| `passive` | Passive recon only |
| `insane` | Maximum intensity |
| `paranoid` | Maximum stealth |
| `polite` | Rate-limited, respectful |
| `http_headless` | Headless browser HTTP scanning |
| `http_record` | HTTP scanning with recording |

```yaml
profiles:
  defaults: [polite]
```

---

## drivers

**Type:** `object`

Execution driver settings.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `drivers.defaults` | `list[str]` | `[]` | Default execution drivers |

```yaml
drivers:
  defaults: [docker]
```

---

## workspace

**Type:** `object`

Workspace settings.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `workspace.default` | `string` | `''` | Default workspace name |

```yaml
workspace:
  default: my-project
```

---

## addons

**Type:** `object`

Optional integrations and addon configurations.

### addons.gdrive — Google Drive

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `addons.gdrive.enabled` | `bool` | `false` | Enable Google Drive integration |
| `addons.gdrive.drive_parent_folder_id` | `string` | `''` | Target Drive folder ID |
| `addons.gdrive.credentials_path` | `string` | `''` | Path to credentials JSON |

### addons.gcs — Google Cloud Storage

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `addons.gcs.enabled` | `bool` | `false` | Enable GCS integration |
| `addons.gcs.bucket_name` | `string` | `''` | GCS bucket name |
| `addons.gcs.credentials_path` | `string` | `''` | Path to credentials JSON |

### addons.worker — Distributed Worker

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `addons.worker.enabled` | `bool` | `false` | Enable distributed worker |

### addons.mongodb — MongoDB

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `addons.mongodb.enabled` | `bool` | `false` | Enable MongoDB integration |
| `addons.mongodb.url` | `string` | `mongodb://localhost` | Connection URL |
| `addons.mongodb.update_frequency` | `int` | `60` | Push interval (s) |
| `addons.mongodb.max_pool_size` | `int` | `10` | Max connection pool size |
| `addons.mongodb.server_selection_timeout_ms` | `int` | `5000` | Server selection timeout (ms) |
| `addons.mongodb.max_items` | `int` | `-1` | Max items stored; `-1` = unlimited |
| `addons.mongodb.duplicate_main_copy_fields` | `list[str]` | `[screenshot_path, stored_response_path, is_false_positive, is_acknowledged, verified, tags]` | Fields copied from duplicate items |

### addons.vulners — Vulners CVE Provider

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `addons.vulners.enabled` | `bool` | `false` | Enable Vulners integration |
| `addons.vulners.api_key` | `string` | `''` | Vulners API key |

### addons.discord — Discord Notifications

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `addons.discord.enabled` | `bool` | `false` | Enable Discord integration |
| `addons.discord.webhook_url` | `string` | `''` | Webhook URL |
| `addons.discord.bot_token` | `string` | `''` | Bot token (alternative to webhook) |
| `addons.discord.send_runner_updates` | `bool` | `true` | Send runner lifecycle events |
| `addons.discord.send_findings` | `bool` | `true` | Send finding notifications |
| `addons.discord.finding_types` | `list[str]` | `[vulnerability]` | Finding types to notify |
| `addons.discord.min_severity` | `string` | `high` | Minimum severity for notifications |

### addons.api — Secator Cloud API

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `addons.api.enabled` | `bool` | `false` | Enable API integration |
| `addons.api.url` | `string` | `https://app.secator.cloud/api` | API base URL |
| `addons.api.key` | `string` | `''` | API key |
| `addons.api.header_name` | `string` | `Bearer` | Auth header scheme |
| `addons.api.force_ssl` | `bool` | `true` | Require TLS |
| `addons.api.timeout` | `int` | `60` | Request timeout (s) |
| `addons.api.runner_create_endpoint` | `string` | `runners` | Runner creation endpoint |
| `addons.api.runner_update_endpoint` | `string` | `runner/{runner_id}` | Runner update endpoint |
| `addons.api.runner_delete_endpoint` | `string` | `{runner_type}/{runner_id}` | Runner delete endpoint |
| `addons.api.finding_create_endpoint` | `string` | `findings` | Finding creation endpoint |
| `addons.api.finding_update_endpoint` | `string` | `finding/{finding_id}` | Finding update endpoint |
| `addons.api.finding_search_endpoint` | `string` | `findings/_search` | Finding search endpoint |
| `addons.api.workspace_get_endpoint` | `string` | `workspace/{workspace_id}` | Workspace fetch endpoint |
| `addons.api.workspace_delete_endpoint` | `string` | `workspace/{workspace_id}` | Workspace delete endpoint |

### addons.ai — AI Assistant

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `addons.ai.enabled` | `bool` | `false` | Enable AI integration |
| `addons.ai.api_key` | `string` | `''` | AI provider API key |
| `addons.ai.api_base` | `string` | `''` | Custom API base URL |
| `addons.ai.default_model` | `string` | `claude-sonnet-4-6` | Default AI model |
| `addons.ai.intent_model` | `string` | `claude-haiku-4-5` | Lightweight intent-detection model |
| `addons.ai.temperature` | `float` | `0.7` | Sampling temperature |
| `addons.ai.max_tokens` | `int` | `30000` | Max tokens per response |
| `addons.ai.max_tokens_total` | `int` | `100000` | Max tokens per session |
| `addons.ai.max_results` | `int` | `500` | Max results passed to AI |
| `addons.ai.user_response_timeout` | `int` | `600` | User interaction timeout (s) |
| `addons.ai.encrypt_pii` | `bool` | `true` | Encrypt PII before sending |
| `addons.ai.permissions` | `dict` | See below | AI permission policy |

**AI permission policy** (`addons.ai.permissions`) has three keys — `allow`, `deny`, and `ask` — each a list of permission rules:

```yaml
addons:
  ai:
    enabled: true
    permissions:
      allow:
        - "target({targets})"
        - "read({workspace}/*,/tmp/*)"
        - "write({workspace}/.outputs/*,/tmp/*)"
        - "shell(curl,wget,dig,nmap,…)"
        - "task(*)"
        - "workflow(*)"
      deny:
        - "target(169.254.169.254)"
        - "target(127.0.0.1)"
        - "read(/etc/shadow)"
        - "read(~/.ssh/*)"
        - "shell(rm -rf /*,dd,mkfs)"
      ask:
        - "target(*)"
        - "shell(python,bash,sh,exec,…)"
        - "read(*)"
        - "write(*)"
```

**Full addon example:**
```yaml
addons:
  mongodb:
    enabled: true
    url: mongodb://localhost:27017/secator
    update_frequency: 30
    max_items: 10000
  discord:
    enabled: true
    webhook_url: https://discord.com/api/webhooks/…
    min_severity: medium
  gdrive:
    enabled: true
    drive_parent_folder_id: 1a2b3c4d5e6f
    credentials_path: ~/.config/gdrive/credentials.json
  vulners:
    enabled: true
    api_key: VULNERS_API_KEY
  ai:
    enabled: true
    api_key: sk-ant-…
    default_model: claude-sonnet-4-6
```

---

## providers

**Type:** `object`

Data provider defaults.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `providers.defaults` | `dict[str, str]` | `{cve: circl, exploit: exploitdb, ghsa: ghsa}` | Default provider per data type |

**Supported providers by type:**

| Type | Options |
|------|---------|
| `cve` | `circl`, `vulners` |
| `exploit` | `exploitdb` |
| `ghsa` | `ghsa` |

```yaml
providers:
  defaults:
    cve: vulners
    exploit: exploitdb
```

---

## security

**Type:** `object`

Security and installation controls.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `security.allow_local_file_access` | `bool` | `true` | Allow files outside the data directory |
| `security.auto_install_commands` | `bool` | `true` | Auto-install missing tools |
| `security.force_source_install` | `bool` | `false` | Build from source instead of binaries |
| `security.prompt_sudo_password` | `bool` | `true` | Prompt for sudo password when needed |

```yaml
security:
  allow_local_file_access: false
  auto_install_commands: true
  force_source_install: false
  prompt_sudo_password: false
```

---

## offline_mode

**Type:** `bool` · **Default:** `false`

When `true`, disables all network activity:
- No wordlist/payload/tool downloads
- No CVE lookups
- No external API calls

```yaml
offline_mode: true
```

---

## Environment Variable Overrides

Every config key can be overridden with an environment variable:

```
SECATOR_<SECTION>_<KEY>=value
```

Dots in the config path become underscores; everything is uppercased.

```bash
# debug
export SECATOR_DEBUG=all

# dirs
export SECATOR_DIRS_DATA=/custom/path
export SECATOR_DIRS_WORDLISTS=/custom/wordlists

# celery
export SECATOR_CELERY_BROKER_URL=redis://localhost:6379/0
export SECATOR_CELERY_WORKER_MAX_TASKS_PER_CHILD=100

# cli
export SECATOR_CLI_GITHUB_TOKEN=ghp_xxxxxxxxxxxx
export SECATOR_CLI_DATE_FORMAT="%d/%m/%Y"

# runners
export SECATOR_RUNNERS_THREADS=200
export SECATOR_RUNNERS_REMOVE_DUPLICATES=true

# security
export SECATOR_SECURITY_AUTO_INSTALL_COMMANDS=false

# offline mode
export SECATOR_OFFLINE_MODE=true
```

Environment variables take precedence over the config file.

---

## Configuration Management

```bash
# View current (non-default) config
secator config get

# View a single key
secator config get dirs.data

# Set a value
secator config set debug all
secator config set celery.worker_max_tasks_per_child 50
secator config set cli.date_format "%d/%m/%Y"

# Reset a value to its default
secator config unset debug

# View full config including defaults
secator config get --full
```

---

## Complete Configuration Example

```yaml
debug: celery,hooks

dirs:
  data: ~/.secator
  wordlists: /custom/wordlists

celery:
  broker_url: redis://localhost:6379/0
  result_backend: redis://localhost:6379/1
  worker_max_tasks_per_child: 50

cli:
  github_token: ghp_xxxxxxxxxxxxxxxxxxxx
  date_format: "%d/%m/%Y"

runners:
  input_chunk_size: 100
  threads: 100
  remove_duplicates: true

http:
  store_responses: true
  response_max_size_bytes: 500000

tasks:
  exporters: [json, csv]
  overrides:
    nmap:
      rate: 1000

workspace:
  default: my-project

providers:
  defaults:
    cve: vulners

addons:
  mongodb:
    enabled: true
    url: mongodb://localhost:27017/secator
    update_frequency: 30
    max_items: 10000
  discord:
    enabled: true
    webhook_url: https://discord.com/api/webhooks/…
    min_severity: medium
  vulners:
    enabled: true
    api_key: VULNERS_API_KEY

security:
  allow_local_file_access: true
  auto_install_commands: true
  prompt_sudo_password: false

offline_mode: false
```
