# Data Model — Output Types

Secator's value proposition is a **unified output schema**: every tool, however
idiosyncratic its native output, is normalized into a small set of typed records.
This file is the authoritative schema spec for a rewrite. Source:
`secator/output_types/`.

---

## 1. The `OutputType` base (`_base.py`)

Every output type is a Python `@dataclass` (default `eq=True, frozen=False`).
Consequences a rewrite must mirror:

- Because `eq=True` + `frozen=False`, instances are **unhashable** (`__hash__ = None`).
  Dedup never uses `hash()`/`set()`; it uses `_compare_key()` (below).
- **Equality is structural over a subset of fields.** Each field can be marked
  `compare=False`; only `compare=True` fields participate in `__eq__`. That comparable
  subset *is the deduplication key* for that type.

### Class-level (non-field) attributes
- `_table_fields: list` — ordered field names shown in table/report rendering.
- `_sort_by: tuple` — field names used to sort findings of this type.

### Internal/meta fields (present on every concrete type, all start with `_`)
| Field | Type | Default | In dedup key? | Meaning |
|---|---|---|---|---|
| `_type` | str | per-class literal | **yes** | Discriminator = `get_name()` (snake_case of class). Ensures types never collide. |
| `_source` | str | `''` | varies* | Producing runner's `unique_name`; set in `add_result` if empty. |
| `_timestamp` | float | `time.time()` | no | Used for "newest wins" in dedup / ordering. |
| `_uuid` | str | `''` | no | Identity tag; `uuid4` assigned in `add_result` if empty. |
| `_context` | dict | `{}` | no | Runner context (ancestor_id, workspace, session…). |
| `_tagged` | bool | `False` | no | Whether tagging hooks ran. **Absent on Info/Warning/Error.** |
| `_duplicate` | bool | `False` | no | Set True on losing duplicates by `mark_duplicates`. |
| `_related` | list | `[]` | no | On the surviving item: `_uuid`s of its duplicates. |

\* `_source` is `compare=True` on `Domain`, `Progress`, `Info`, `Warning`, `Error`, but
`compare=False` on most finding types. **The `compare` flags are deliberately
inconsistent per type — replicate them exactly.**

`INTERNAL_FIELDS = ('_context', '_uuid', '_related', '_duplicate')` (used for filtering).

### Base methods (the serialization/identity contract)
- `fields()` / `keys()` → list of all field names.
- `toDict(exclude=[])` → shallow copy of `__dict__` (includes `_` fields). **No nested
  serialization**; datetimes/enums are stringified later at the JSON layer
  (`json.dumps(..., default=str)`).
- `load(cls, item: dict, output_map={})` → the "fromDict":
  - If `item['_type']` set and ≠ `cls.get_name()` → raise `TypeError`.
  - For each field: if in `output_map`, value is `output_map[key](item)` (callable) or
    `item[output_map[key]]` (rename); else if field name in `item`, copy it.
  - If **all** resolved values are `None` → raise `TypeError` (→ caller tries next type).
  - Set `_type` and return `cls(**new_item)`.
- `get_name(cls)` → CamelCase→snake_case (`UserAccount`→`user_account`). The canonical
  `_type` string and reconstruction join key.
- `_compare_key()` → hashable tuple of `compare=True` fields (`dict`→sorted-items tuple,
  `list`→tuple). The O(1) dedup grouping key.
- Ordering: `a > b` is False unless `a == b` (same dedup key); when equal, `a > b` ⇔
  `a._timestamp > b._timestamp` (newest is "greater"). Some types override to prefer a
  source (`Url`→httpx, `Port`→nmap).
- `merge_with(other, exclude_fields=[])` → enrich self from another instance: skip
  empty, union lists, merge dicts, overwrite scalars.
- `__post_init__()` → normalize any `None` field to its default/default_factory; then
  subtypes add their own normalization (calling `super().__post_init__()` first —
  except `Target`, which doesn't).
- Rendering: `__str__` (short id), `__rich__` (rich markup), `__repr__` =
  `rich_to_ansi(__rich__())`.
- `validate_fields(data)` / `schema()` — dev/introspection helpers.

---

## 2. Type registry (`__init__.py`)

```python
EXECUTION_TYPES = [Target, Progress, Info, Warning, Error, State]
STAT_TYPES      = [Stat]
FINDING_TYPES   = [Subdomain, Ip, Port, Url, Tag, Exploit, UserAccount,
                   Vulnerability, Certificate, Record, Domain, Ai, Technology]
OUTPUT_TYPES    = FINDING_TYPES + EXECUTION_TYPES + STAT_TYPES
```

- **Findings** = the security-relevant results, persisted/exported/deduped.
- **Execution** = control/observability items (targets, progress, logs, state).
- **Stat** = process resource samples.

Reconstruction from a dict: find `cls` in `OUTPUT_TYPES` where `cls.get_name() ==
item['_type']`, then `cls.load(item)`.

---

## 3. Finding types (field specs)

Notation: `name: type = default`. **[K]** marks a field in the dedup key
(`compare=True`); `_type` is always in the key. Unmarked finding-data fields are
`compare=False`.

### Subdomain — `_type='subdomain'`
Key: `host`, `domain`. `host: str` **[K]**, `domain: str` **[K]**, `verified: bool=False`,
`sources: list=[]`, `extra_data: dict={}`, `is_false_positive=False`,
`is_acknowledged=False`, `tags: list=[]`.

### Ip — `_type='ip'`
Key: `ip`, `alive`, `protocol`. `ip: str` **[K]**, `host: str=''`, `alive: bool=False`
**[K]**, `protocol: str=IpProtocol.IPv4` **[K]** (`str`-Enum IPv4/IPv6), `extra_data={}`,
`is_false_positive`, `is_acknowledged`, `tags`.

### Port — `_type='port'`
Key: `port`, `ip`, `state`. `port: int` **[K]**, `ip: str` **[K]**, `state: str='UNKNOWN'`
**[K]**, `service_name=''`, `cpes: list=[]`, `host=''`, `protocol='tcp'`, `extra_data={}`,
`confidence='low'`, `service_confidence='low'`, `is_false_positive`, `is_acknowledged`,
`tags`. `__str__`→`{host}:{port}`. Overrides `__gt__` to prefer `_source=='nmap'`.

### Url — `_type='url'`
Key: **`url` only** (everything else `compare=False`). Required `url: str` **[K]**, plus
`host`, `verified`, `status_code`, `title`, `protocol`, `webserver`, `tech: list`,
`content_type`, `content_length`, `time`, `method`, `words`, `lines`, `screenshot_path`,
`stored_response_path`, `confidence='high'`, `response_headers: dict`,
`request_headers: dict`, `extra_data: dict`, `is_directory`, `is_root`, `is_redirect`,
`is_false_positive`, `is_acknowledged`, `tags`.
`__post_init__`: derive `host` from url; set `protocol`; `verified=True` if
confidence high + status_code≠0; detect directory (`'Index of'`); detect root url;
extract `webserver`/`content_type`/`content_length` from `response_headers` (then
title-case header keys); append webserver to tech. Overrides `__gt__` to prefer httpx.
`get_techs()` yields `Technology` per tech entry.

### Tag — `_type='tag'`
Key: `name`, `value`, `match`, `category`. `name` **[K]**, `value` **[K]**, `match` **[K]**,
`category='general'` **[K]**, `extra_data={}`, `stored_response_path=''`,
`is_false_positive`, `is_acknowledged`, `tags`. The generic "something matched here"
finding (pattern hits, WAF detections, secrets, etc.).

### Exploit — `_type='exploit'`
Key: `name`, `provider`, `id`, `matched_at`, `ip`, `confidence`. + `reference=''`,
`cves: list=[]`, `tags`, `extra_data`, `is_false_positive`, `is_acknowledged`.

### UserAccount — `_type='user_account'`
Key: `username`, `url`, `email`, `site_name`. + `extra_data`, `is_false_positive`,
`is_acknowledged`, `tags`.

### Vulnerability — `_type='vulnerability'`
Key: `name`, `provider`, `id`, `matched_at`, `confidence`, `severity`, `cvss_score`,
`cvss_vec`, `epss_score`, `confidence_nb`, `severity_nb` (i.e. all not explicitly
`compare=False`). Non-key: `ip` (compare=False), `extra_data`, `description`,
`references: list`, `reference`, `is_false_positive`, `is_acknowledged`, `tags`.
`__post_init__`: `reference←references[0]`; derive `severity` from cvss if unknown;
lowercase severity; compute `severity_nb`/`confidence_nb` from a fixed ordinal map
(`critical=0…unknown=5, None=6`). `cvss_to_severity`: `<4 low, <7 medium, <9 high, else
critical`. CVE/CPE comparison logic lives in `secator/cve.py`, invoked by tasks (not in
the dataclass). `__str__`→`{matched_at} -> {name}`.

### Certificate — `_type='certificate'`
Key: `host`, `fingerprint_sha256`. + `ip`, `raw_value`, `subject_cn`, `subject_an: list`,
`not_before: datetime`, `not_after: datetime`, `issuer_dn/cn/issuer`, `self_signed=True`,
`trusted=False`, `status='Unknown'`, `keysize`, `serial_number`, `ciphers: list`.
`__post_init__` parses dates to UTC. Methods: `is_expired(months)`, `is_wildcard()`,
`get_vulnerabilities()` → yields a `Vulnerability` when expired.

### Record — `_type='record'` (DNS record)
Key: `name`, `type`, `host`. + `extra_data`, `is_false_positive`, `is_acknowledged`,
`tags`.

### Domain — `_type='domain'`
Key: `domain`, `alive` (**and `_source` — compare=True here**). + whois fields:
`creation_date/expiration_date/updated_date: datetime`, `status: list`, `registrar`,
`registrar_info: dict`, `registrant`, `registrant_info`, `administrative_info`,
`technical_info`, `extra_data`, flags, `tags`. `__post_init__` parses dates; computes
`alive` from status.

### Ai — `_type='ai'`
Key: `content`, `ai_type`. + `mode`, `model`, `extra_data`, `summary=False`, `status`,
`answer`, `choices: list`, `session_id`. `ai_type ∈ {prompt, response, summary,
suggestion, attack_summary, token_usage, …}`. Elaborate rich rendering (markdown panels,
token/cost). No `_tagged`. The AI subsystem's output record.

### Technology — `_type='technology'`
Key: `product`, `match`, `version`. + `extra_data`, `tags`. Produced by `Url.get_techs()`.

---

## 4. Execution types

### Target — `_type='target'`
Key: `name`, `type`. `__post_init__` (no super call): `type←autodetect_type(name)` if
empty. The root inputs are materialized as `Target` items at runner init.

### Progress — `_type='progress'`
Key: `percent`, `_source`. + `extra_data`. `__post_init__` clamps percent to [0,100].
Drives the runner's `progress` field (throttled by `progress_update_frequency`).

### Info / Warning / Error — `_type='info'|'warning'|'error'`
`message: str` (required, in key). `_source` is `compare=True`. **No `_tagged`.**
- `Info` also has `task_id`.
- `Warning` stores `message_color` (markup) + plain `message`.
- `Error` has `traceback`, `traceback_title`, and `Error.from_exception(e, **kw)`.

### State — `_type='state'`
Key: `task_id`, `state`. Celery task state. `add_result` special-cases it: when
`task_id` matches the runner's celery result id and `state ∈ {RUNNING, SUCCESS, FAILURE,
REVOKED}`, it updates the runner's started/done/progress.

### Stat — `_type='stat'`
Key: all data fields (`name`, `pid`, `cpu`, `memory`, `memory_limit`, `net_conns`,
`extra_data`). Process resource sample emitted by the Command monitor thread.

---

## 5. Relationships (denormalized, by value)

There are **no embedded object references** — all cross-links are string fields:
- `Port.ip/.host` → `Ip`; `Vulnerability.ip`, `Exploit.ip`, `Certificate.ip` → `Ip`.
- `Url.host` → host/Ip; `Url.tech` (strings) → `Technology` via `get_techs()`.
- `Subdomain.domain` ↔ `Domain.domain`.
- `Tag.match` / `Technology.match` / `UserAccount.url` / `Vulnerability.matched_at` →
  a free-form locator (url/host/ip).
- `Exploit.cves` (strings) → CVE ids.
- `Record.name/.host` → DNS host.

**Generative relationships** (a type emits another): `Certificate.get_vulnerabilities()`
→ `Vulnerability`; `Url.get_techs()` → `Technology`.

A rewrite can keep this denormalized string-FK model (it makes dedup and export simple)
or introduce real references — but the dedup keys above assume the denormalized form.

---

## 6. Deduplication across a workflow

1. **Identity** (`add_result`): assign `_uuid`, `_source`, merge `_context`; drop if
   `_uuid` already seen.
2. **Where it runs**: `enable_duplicate_check` is **True** on the base Runner but set
   **False** on Task and Workflow — so dedup happens in the aggregating owner (Scan, or
   the top-level runner) which has all results.
3. **`mark_duplicates()`** (O(n), at `mark_completed`): group results by `_compare_key()`;
   in each group >1, `main = max(items)` (newest by timestamp, with source-preference
   overrides); losers get `_duplicate=True` and their uuids appended to `main._related`;
   `on_item`/`on_duplicate` hooks fire.
4. **`remove_duplicates(items)`** (`utils.py`): standalone first-wins dedup by
   `_compare_key()` (handles dict items by loading via `_type`), used for inputs/merges.

### Gotchas for the rewrite
- Never hash findings; use the per-type comparable-field tuple.
- `compare` flags vary per type (e.g. `confidence` is keyed on Exploit/Vulnerability but
  not Url; `_source` is keyed on Domain/Progress/log types only; `extra_data` is keyed
  only on Stat). Port each type's key faithfully.
- `Vulnerability.confidence_nb` indexes the **severity** ordinal map by the *confidence*
  string (confidence reuses the severity scale; an unknown value raises `KeyError`).
- `__post_init__` order: base `None`→default normalization first, then subtype logic
  (Target excepted).
- `toDict()` is shallow; serialization of datetimes/enums happens at the JSON boundary.
