# Secator Configuration Documentation

This document provides detailed information about all configuration options available in Secator. The configuration is stored in `~/.secator/config.yml` by default.

## Table of Contents

- [Configuration File Location](#configuration-file-location)
- [Configuration Fields](#configuration-fields)
  - [debug](#debug)
  - [dirs](#dirs)
  - [celery](#celery)
  - [cli](#cli)
  - [runners](#runners)
  - [http](#http)
  - [tasks](#tasks)
  - [workflows](#workflows)
  - [scans](#scans)
  - [payloads](#payloads)
  - [wordlists](#wordlists)
  - [profiles](#profiles)
  - [drivers](#drivers)
  - [addons](#addons)
  - [security](#security)
  - [offline_mode](#offline_mode)
- [Environment Variable Overrides](#environment-variable-overrides)

## Configuration File Location

Secator stores its configuration in:
- **Default location**: `~/.secator/config.yml`
- **Can be overridden** via the `SECATOR_DIRS_DATA` environment variable

The configuration file is automatically created when you first run Secator. You can edit it directly or use the `secator config` commands.

## Configuration Fields

### debug

**Type**: `string`  
**Default**: `''` (empty string)

Controls debug output during execution. Set to a comma-separated list of debug components to enable verbose logging for specific parts of the application.

**Possible values**:
- `''` (empty) - No debug output
- `'all'` or `'1'` - Enable all debug output
- Comma-separated component names (e.g., `'celery,hooks'`)

**Available debug components**:
- `celery` - Celery task execution
- `celery.app` - Celery application initialization
- `celery.data` - Celery data operations
- `celery.poll` - Celery polling operations
- `celery.state` - Celery state management
- `cli` - CLI operations
- `config` - Configuration loading and parsing
- `cve` - CVE operations
- `cve.circl` - CIRCL CVE provider
- `cve.match` - CVE matching
- `cve.nmap` - Nmap CVE detection
- `cve.provider` - CVE provider operations
- `cve.vulners` - Vulners CVE provider
- `debug.celery` - Celery debugging
- `debug.klass.load` - Class loading
- `duplicates` - Duplicate detection
- `end` - Task completion
- `error` - Error handling
- `extractor` - Output extraction
- `extractors` - Output extractors
- `hooks` - Hook execution
- `hooks.gcs` - Google Cloud Storage hooks
- `hooks.mongodb` - MongoDB hooks
- `init` - Initialization
- `init.options` - Option initialization
- `installer` - Tool installation
- `item` - Item processing
- `item.convert` - Item conversion
- `item.duplicate` - Item duplication
- `line.print` - Line printing
- `line.process` - Line processing
- `monitor` - Monitoring operations
- `run` - Task execution
- `start` - Task start
- `stats` - Statistics
- `template` - Template operations
- `unittest` - Unit testing
- `unittest.dict` - Dictionary testing
- `unittest.item` - Item testing
- `validators` - Validation operations

You can also use wildcards, e.g., `'cve.*'` to match all CVE-related components.

**Examples**:
```yaml
debug: all                    # Enable all debug output
debug: celery,hooks          # Debug Celery and hooks only
debug: cve.*                 # Debug all CVE components
```

---

### dirs

**Type**: `object`  
**Description**: Directory paths used by Secator for storing data, tools, and artifacts.

All directory paths support tilde (`~`) expansion for the home directory.

#### dirs.bin

**Type**: `Path`  
**Default**: `~/.local/bin`

Directory for storing binary executables of security tools.

#### dirs.share

**Type**: `Path`  
**Default**: `~/.local/share`

Directory for storing shared data files.

#### dirs.data

**Type**: `Path`  
**Default**: `~/.secator` (or value of `SECATOR_DIRS_DATA` env var)

Root data directory for Secator. All other directories default to subdirectories of this path if not explicitly set.

#### dirs.templates

**Type**: `Path`  
**Default**: `{dirs.data}/templates`

Directory for workflow and scan templates.

#### dirs.reports

**Type**: `Path`  
**Default**: `{dirs.data}/reports`

Directory where generated reports are stored.

#### dirs.wordlists

**Type**: `Path`  
**Default**: `{dirs.data}/wordlists`

Directory for storing wordlists used in fuzzing and enumeration tasks.

#### dirs.cves

**Type**: `Path`  
**Default**: `{dirs.data}/cves`

Directory for storing CVE data.

#### dirs.payloads

**Type**: `Path`  
**Default**: `{dirs.data}/payloads`

Directory for storing exploit payloads and scripts.

#### dirs.performance

**Type**: `Path`  
**Default**: `{dirs.data}/performance`

Directory for storing performance metrics and profiling data.

#### dirs.revshells

**Type**: `Path`  
**Default**: `{dirs.data}/revshells`

Directory for storing reverse shell payloads.

#### dirs.celery

**Type**: `Path`  
**Default**: `{dirs.data}/celery`

Directory for Celery broker files (when using filesystem broker).

#### dirs.celery_data

**Type**: `Path`  
**Default**: `{dirs.data}/celery/data`

Directory for Celery data files.

#### dirs.celery_results

**Type**: `Path`  
**Default**: `{dirs.data}/celery/results`

Directory for Celery result backend files.

**Example**:
```yaml
dirs:
  data: ~/.secator
  bin: ~/.local/bin
  wordlists: /custom/path/to/wordlists
```

---

### celery

**Type**: `object`  
**Description**: Configuration for Celery distributed task queue used for running tasks asynchronously.

#### celery.broker_url

**Type**: `string`  
**Default**: `'filesystem://'`

URL for the Celery message broker. Supported brokers include filesystem, Redis, RabbitMQ, etc.

**Examples**:
- `'filesystem://'` - File system broker
- `'redis://localhost:6379/0'` - Redis broker
- `'amqp://guest:guest@localhost:5672//'` - RabbitMQ broker

#### celery.broker_pool_limit

**Type**: `integer`  
**Default**: `10`

Maximum number of connections to keep in the broker connection pool.

#### celery.broker_connection_timeout

**Type**: `float`  
**Default**: `4.0`

Timeout in seconds for establishing connections to the broker.

#### celery.broker_visibility_timeout

**Type**: `integer`  
**Default**: `3600` (1 hour)

Number of seconds to wait for the worker to acknowledge the task before the message is redelivered.

#### celery.broker_transport_options

**Type**: `string`  
**Default**: `''` (empty string)

JSON string of additional broker transport options. Format depends on the broker backend.

#### celery.override_default_logging

**Type**: `boolean`  
**Default**: `true`

Whether to override Celery's default logging configuration with Secator's logging.

#### celery.result_backend

**Type**: `string`  
**Default**: `'file://{dirs.celery_results}'`

URL for the Celery result backend where task results are stored.

**Examples**:
- `'file:///tmp/celery_results'` - File system backend
- `'redis://localhost:6379/1'` - Redis backend
- `'mongodb://localhost:27017/celery'` - MongoDB backend

#### celery.result_backend_transport_options

**Type**: `string`  
**Default**: `''` (empty string)

JSON string of additional result backend transport options.

#### celery.result_expires

**Type**: `integer`  
**Default**: `86400` (1 day in seconds)

Time in seconds before task results expire and are removed from the backend.

#### celery.task_acks_late

**Type**: `boolean`  
**Default**: `false`

If `true`, tasks are acknowledged after execution. If `false`, tasks are acknowledged before execution.

#### celery.task_send_sent_event

**Type**: `boolean`  
**Default**: `false`

Whether to send task-sent events. Can increase overhead.

#### celery.task_reject_on_worker_lost

**Type**: `boolean`  
**Default**: `false`

Whether to reject tasks if worker connection is lost.

#### celery.task_max_timeout

**Type**: `integer`  
**Default**: `-1` (unlimited)

Maximum time in seconds a task can run. Set to `-1` for no limit.

#### celery.task_memory_limit_mb

**Type**: `integer`  
**Default**: `-1` (unlimited)

Maximum memory in megabytes a task can use. Set to `-1` for no limit.

#### celery.worker_max_tasks_per_child

**Type**: `integer`  
**Default**: `20`

Maximum number of tasks a worker process executes before being recycled. Helps prevent memory leaks.

#### celery.worker_prefetch_multiplier

**Type**: `integer`  
**Default**: `1`

Number of tasks to prefetch per worker process. Lower values provide better task distribution.

#### celery.worker_send_task_events

**Type**: `boolean`  
**Default**: `false`

Whether workers should send task events for monitoring. Can increase overhead.

#### celery.worker_kill_after_task

**Type**: `boolean`  
**Default**: `false`

Whether to kill the worker after each task. Useful for debugging memory issues.

#### celery.worker_kill_after_idle_seconds

**Type**: `integer`  
**Default**: `-1` (disabled)

Kill worker after being idle for this many seconds. Set to `-1` to disable.

#### celery.worker_command_verbose

**Type**: `boolean`  
**Default**: `false`

Whether to show verbose output when running worker commands.

**Example**:
```yaml
celery:
  broker_url: redis://localhost:6379/0
  result_backend: redis://localhost:6379/1
  worker_max_tasks_per_child: 50
  result_expires: 172800  # 2 days
```

---

### cli

**Type**: `object`  
**Description**: Configuration for CLI (Command Line Interface) behavior.

#### cli.github_token

**Type**: `string`  
**Default**: Value of `GITHUB_TOKEN` environment variable or `''`

GitHub personal access token for accessing GitHub API (e.g., for downloading tools).

#### cli.record

**Type**: `boolean`  
**Default**: `false`

Whether to record CLI sessions (used with asciinema or similar tools).

#### cli.stdin_timeout

**Type**: `integer`  
**Default**: `1000` (milliseconds)

Timeout in milliseconds when waiting for stdin input.

#### cli.show_http_response_headers

**Type**: `boolean`  
**Default**: `false`

Whether to display HTTP response headers in CLI output.

#### cli.show_command_output

**Type**: `boolean`  
**Default**: `false`

Whether to display raw command output in addition to parsed results.

#### cli.exclude_http_response_headers

**Type**: `list of strings`  
**Default**: `["connection", "content_type", "content_length", "date", "server"]`

List of HTTP header names to exclude from output when `show_http_response_headers` is enabled.

**Example**:
```yaml
cli:
  github_token: ghp_xxxxxxxxxxxxxxxxxxxx
  show_http_response_headers: true
  exclude_http_response_headers: ["date", "server"]
```

---

### runners

**Type**: `object`  
**Description**: Configuration for task runners that execute security tools.

#### runners.input_chunk_size

**Type**: `integer`  
**Default**: `100`

Number of inputs to process in each chunk when running tasks with multiple inputs.

#### runners.progress_update_frequency

**Type**: `integer`  
**Default**: `20`

Frequency (in number of processed items) at which to update progress display.

#### runners.stat_update_frequency

**Type**: `integer`  
**Default**: `20`

Frequency (in number of processed items) at which to update statistics.

#### runners.backend_update_frequency

**Type**: `integer`  
**Default**: `5`

Frequency (in seconds) at which to update backend storage (e.g., MongoDB).

#### runners.poll_frequency

**Type**: `integer`  
**Default**: `5`

Frequency (in seconds) at which to poll for task status in distributed mode.

#### runners.skip_cve_search

**Type**: `boolean`  
**Default**: `false`

Whether to skip CVE enrichment for discovered vulnerabilities.

#### runners.skip_exploit_search

**Type**: `boolean`  
**Default**: `false`

Whether to skip exploit search for discovered vulnerabilities.

#### runners.skip_cve_low_confidence

**Type**: `boolean`  
**Default**: `false`

Whether to skip CVEs with low confidence scores.

#### runners.remove_duplicates

**Type**: `boolean`  
**Default**: `false`

Whether to automatically remove duplicate results.

**Example**:
```yaml
runners:
  input_chunk_size: 50
  skip_cve_search: false
  remove_duplicates: true
```

---

### http

**Type**: `object`  
**Description**: Configuration for HTTP requests and proxy settings.

#### http.socks5_proxy

**Type**: `string`  
**Default**: `'socks5://127.0.0.1:9050'`

Default SOCKS5 proxy URL (typically for Tor).

#### http.http_proxy

**Type**: `string`  
**Default**: `'https://127.0.0.1:9080'`

Default HTTP/HTTPS proxy URL.

#### http.store_responses

**Type**: `boolean`  
**Default**: `true`

Whether to store HTTP responses to disk for later analysis.

#### http.response_max_size_bytes

**Type**: `integer`  
**Default**: `100000` (100 KB)

Maximum size in bytes for storing HTTP response bodies. Larger responses are truncated.

#### http.proxychains_command

**Type**: `string`  
**Default**: `'proxychains'`

Command name for proxychains tool used for proxying applications.

#### http.freeproxy_timeout

**Type**: `integer`  
**Default**: `1` (second)

Timeout when testing free proxy servers.

**Example**:
```yaml
http:
  socks5_proxy: socks5://127.0.0.1:9050
  http_proxy: http://proxy.example.com:8080
  store_responses: true
  response_max_size_bytes: 500000
```

---

### tasks

**Type**: `object`  
**Description**: Configuration for individual security tasks.

#### tasks.exporters

**Type**: `list of strings`  
**Default**: `['json', 'csv', 'txt']`

List of export formats available for task outputs.

**Example**:
```yaml
tasks:
  exporters: ['json', 'csv', 'html']
```

---

### workflows

**Type**: `object`  
**Description**: Configuration for workflows (chains of tasks).

#### workflows.exporters

**Type**: `list of strings`  
**Default**: `['json', 'csv', 'txt']`

List of export formats available for workflow outputs.

**Example**:
```yaml
workflows:
  exporters: ['json', 'csv']
```

---

### scans

**Type**: `object`  
**Description**: Configuration for scans (complex multi-workflow operations).

#### scans.exporters

**Type**: `list of strings`  
**Default**: `['json', 'csv', 'txt']`

List of export formats available for scan outputs.

**Example**:
```yaml
scans:
  exporters: ['json']
```

---

### payloads

**Type**: `object`  
**Description**: Configuration for payload management and templates.

#### payloads.templates

**Type**: `object (dict)`  
**Default**:
```yaml
lse: https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh
linpeas: https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
sudo_killer: https://github.com/TH3xACE/SUDO_KILLER/archive/refs/heads/V3.zip
```

Dictionary mapping payload names to their download URLs or paths. Payloads can be:
- HTTP/HTTPS URLs (automatically downloaded)
- Git repositories (prefix with `git+`)
- Local file paths

**Example**:
```yaml
payloads:
  templates:
    custom_payload: https://example.com/payload.sh
    custom_repo: git+https://github.com/user/repo.git
    local_script: /path/to/local/script.sh
```

---

### wordlists

**Type**: `object`  
**Description**: Configuration for wordlist management and templates.

#### wordlists.defaults

**Type**: `object (dict)`  
**Default**:
```yaml
http: bo0m_fuzz
dns: combined_subdomains
http_params: burp-parameter-names
```

Dictionary mapping wordlist types to their default wordlist names.

#### wordlists.templates

**Type**: `object (dict)`  
**Default**:
```yaml
bo0m_fuzz: https://raw.githubusercontent.com/Bo0oM/fuzz.txt/master/fuzz.txt
combined_subdomains: https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/combined_subdomains.txt
directory_list_small: https://gist.githubusercontent.com/sl4v/c087e36164e74233514b/raw/c51a811c70bbdd87f4725521420cc30e7232b36d/directory-list-2.3-small.txt
burp-parameter-names: https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/burp-parameter-names.txt
```

Dictionary mapping wordlist names to their download URLs or paths. Similar to payloads, wordlists support:
- HTTP/HTTPS URLs
- Git repositories (prefix with `git+`)
- Local file paths

#### wordlists.lists

**Type**: `object (dict)`  
**Default**: `{}`

Dictionary for storing custom inline wordlists as lists of strings.

**Example**:
```yaml
wordlists:
  defaults:
    http: my_custom_wordlist
  templates:
    my_custom_wordlist: https://example.com/wordlist.txt
  lists:
    inline_list: ['admin', 'test', 'api']
```

---

### profiles

**Type**: `object`  
**Description**: Configuration profiles that modify task behavior.

#### profiles.defaults

**Type**: `list of strings`  
**Default**: `[]`

List of profile names to apply by default. Profiles can modify scan intensity, stealth, etc.

**Available profiles** (in `secator/configs/profiles/`):
- `aggressive` - Fast, noisy scans
- `sneaky` - Slow, stealthy scans
- `passive` - Passive reconnaissance only
- `insane` - Maximum intensity
- `paranoid` - Maximum stealth
- `polite` - Rate-limited, respectful scans
- `http_headless` - HTTP scanning with headless browsers
- `http_record` - HTTP scanning with recording

**Example**:
```yaml
profiles:
  defaults: ['polite']
```

---

### drivers

**Type**: `object`  
**Description**: Configuration for execution drivers (container, VM, etc.).

#### drivers.defaults

**Type**: `list of strings`  
**Default**: `[]`

List of default drivers to use for task execution.

**Example**:
```yaml
drivers:
  defaults: ['docker']
```

---

### addons

**Type**: `object`  
**Description**: Configuration for optional addons and integrations.

#### addons.gdrive

**Type**: `object`  
**Description**: Google Drive integration for storing results.

##### addons.gdrive.enabled

**Type**: `boolean`  
**Default**: `false`

Whether Google Drive addon is enabled.

##### addons.gdrive.drive_parent_folder_id

**Type**: `string`  
**Default**: `''`

Google Drive folder ID where results should be stored.

##### addons.gdrive.credentials_path

**Type**: `string`  
**Default**: `''`

Path to Google Drive API credentials JSON file.

#### addons.gcs

**Type**: `object`  
**Description**: Google Cloud Storage integration for storing results.

##### addons.gcs.enabled

**Type**: `boolean`  
**Default**: `false`

Whether Google Cloud Storage addon is enabled.

##### addons.gcs.bucket_name

**Type**: `string`  
**Default**: `''`

Name of the GCS bucket for storing results.

##### addons.gcs.credentials_path

**Type**: `string`  
**Default**: `''`

Path to GCS credentials JSON file.

#### addons.worker

**Type**: `object`  
**Description**: Distributed worker addon for horizontal scaling.

##### addons.worker.enabled

**Type**: `boolean`  
**Default**: `false`

Whether distributed worker addon is enabled.

#### addons.mongodb

**Type**: `object`  
**Description**: MongoDB integration for storing results.

##### addons.mongodb.enabled

**Type**: `boolean`  
**Default**: `false`

Whether MongoDB addon is enabled.

##### addons.mongodb.url

**Type**: `string`  
**Default**: `'mongodb://localhost'`

MongoDB connection URL.

##### addons.mongodb.update_frequency

**Type**: `integer`  
**Default**: `60` (seconds)

Frequency at which to push results to MongoDB.

##### addons.mongodb.max_pool_size

**Type**: `integer`  
**Default**: `10`

Maximum size of MongoDB connection pool.

##### addons.mongodb.server_selection_timeout_ms

**Type**: `integer`  
**Default**: `5000` (5 seconds)

Timeout in milliseconds for MongoDB server selection.

**Example**:
```yaml
addons:
  mongodb:
    enabled: true
    url: mongodb://localhost:27017/secator
    update_frequency: 30
  gdrive:
    enabled: true
    drive_parent_folder_id: 1a2b3c4d5e6f
    credentials_path: ~/.config/gdrive/credentials.json
```

---

### security

**Type**: `object`  
**Description**: Security-related configuration options.

#### security.allow_local_file_access

**Type**: `boolean`  
**Default**: `true`

Whether to allow access to local files outside the Secator data directory. If `false`, wordlists and payloads must be within the data directory.

#### security.auto_install_commands

**Type**: `boolean`  
**Default**: `true`

Whether to automatically install missing security tools when needed.

#### security.force_source_install

**Type**: `boolean`  
**Default**: `false`

Whether to force installation from source instead of using pre-built binaries.

**Example**:
```yaml
security:
  allow_local_file_access: false
  auto_install_commands: true
  force_source_install: false
```

---

### offline_mode

**Type**: `boolean`  
**Default**: `false`

Whether to run in offline mode. When enabled:
- No network requests for downloading wordlists, payloads, or tools
- No CVE lookups
- No external API calls

**Example**:
```yaml
offline_mode: true
```

---

## Environment Variable Overrides

Any configuration value can be overridden using environment variables with the prefix `SECATOR_`. The variable name should be the configuration path in uppercase with dots replaced by underscores.

**Examples**:
```bash
# Override debug setting
export SECATOR_DEBUG=all

# Override directories
export SECATOR_DIRS_DATA=/custom/path
export SECATOR_DIRS_WORDLISTS=/custom/wordlists

# Override Celery settings
export SECATOR_CELERY_BROKER_URL=redis://localhost:6379/0
export SECATOR_CELERY_WORKER_MAX_TASKS_PER_CHILD=100

# Override CLI settings
export SECATOR_CLI_GITHUB_TOKEN=ghp_xxxxxxxxxxxx

# Override security settings
export SECATOR_SECURITY_AUTO_INSTALL_COMMANDS=false
```

Environment variable overrides take precedence over the configuration file values.

---

## Configuration Management Commands

Secator provides CLI commands for managing configuration:

```bash
# View current configuration
secator config get

# View specific configuration key
secator config get dirs.data

# Set a configuration value
secator config set debug all
secator config set celery.worker_max_tasks_per_child 50

# Reset a value to default
secator config unset debug

# View full configuration including defaults
secator config get --full
```

---

## Example Complete Configuration

Here's an example of a complete configuration file:

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
  show_http_response_headers: false

runners:
  input_chunk_size: 100
  skip_cve_search: false
  remove_duplicates: true

http:
  store_responses: true
  response_max_size_bytes: 500000

addons:
  mongodb:
    enabled: true
    url: mongodb://localhost:27017/secator
    update_frequency: 30

security:
  allow_local_file_access: true
  auto_install_commands: true

offline_mode: false
```
