# Design: search_vulns Input Grouping via Extractor `group_by`

**Date:** 2026-04-17
**Branch:** improve-search-vulns-grouping

## Problem

In large scans (e.g. `10.0.0.0/8`), `host_recon` dispatches one `search_vulns` task per `Technology`
item. Many hosts share the same `{product} {version}`, causing N redundant subprocess calls for
identical queries. For 1000 hosts all running `Apache httpd 2.4.50`, this fires 1000 separate
`search_vulns -q "Apache httpd 2.4.50"` processes.

## Approach: Extractor `group_by` (nmap-inspired)

Mirrors the nmap `targets_` / `ports_` split in `host_recon.yaml`. nmap deduplicates hosts via the
extractor's built-in `deduplicate()` and receives all relevant ports as a single option. We apply
the same principle to `search_vulns`: group all `{match}` values (host:port) that share the same
`{product} {version}`, producing one input per unique service.

### Input format (unchanged `~` convention)

```text
Before grouping (current):
  10.0.0.1:80~Apache httpd 2.4.50
  10.0.0.2:80~Apache httpd 2.4.50
  10.0.0.3:80~nginx 1.21.0

After grouping (proposed):
  10.0.0.1:80,10.0.0.2:80~Apache httpd 2.4.50
  10.0.0.3:80~nginx 1.21.0
```

One `search_vulns` subprocess per unique service; results fanned out to all matching hosts.

## Changes

### 1. `secator/runners/_helpers.py`

Add `group_by` to `parse_extractor` and `process_extractor`.

**`parse_extractor`:** return a 4-tuple `(_type, _field, _condition, _group_by)`.

**`process_extractor`:** after filtering and field-formatting, if `_group_by` is set:
1. Re-evaluate each result item against the `_group_by` template to get the group key
2. Build a `dict[key → list[formatted_field_value]]`
3. Return one entry per key: join the field values that appear before `~` with `,`,
   keeping everything after `~` as the key suffix

Concretely for `field: '{match}~{product} {version}'` and `group_by: '{product} {version}'`:

```python
groups = {}  # key: "Apache httpd 2.4.50", value: ["10.0.0.1:80", "10.0.0.2:80"]
for item in filtered_results:
    key   = group_by_tpl.format(**item.toDict())   # "Apache httpd 2.4.50"
    value = field_tpl.format(**item.toDict())       # "10.0.0.1:80~Apache httpd 2.4.50"
    match_part = value.split('~')[0]               # "10.0.0.1:80"
    groups.setdefault(key, []).append(match_part)

return [','.join(hosts) + '~' + svc for svc, hosts in groups.items()]
```

`deduplicate()` in `run_extractors` then deduplicates across multiple extractor entries if needed.

### 2. `secator/configs/workflows/host_recon.yaml`

Add `group_by` to both `search_vulns` and `searchsploit` technology extractors:

```yaml
search_vulns:
  targets_:
    - type: vulnerability
      field: '{matched_at}~{id}'
      condition: item.id
    - type: technology
      field: '{match}~{product} {version}'
      condition: item.version
      group_by: '{product} {version}'   # NEW

searchsploit:
  targets_:
    - type: vulnerability
      field: '{matched_at}~{id}'
      condition: item.id
    - type: technology
      field: '{match}~{product} {version}'
      condition: item.version
      group_by: '{product} {version}'   # NEW
```

### 3. `secator/tasks/search_vulns.py`

**`before_init`:** already splits on `~`; `self.matched_at` now holds a comma-separated host list.
No structural change needed — just ensure the rest of the method handles multiple hosts correctly
(the `inputs[0]` replacement remains the same).

**`on_json_loaded`:** fan results out to all hosts in `matched_at`:

```python
# Current (single host):
matched_at = self.matched_at if self.matched_at else self.inputs[0] if self.inputs else ''
yield Vulnerability(**{..., 'matched_at': matched_at})

# Proposed (multiple hosts):
matched_at_raw = self.matched_at if self.matched_at else self.inputs[0] if self.inputs else ''
matched_ats = matched_at_raw.split(',')
for matched_at in matched_ats:
    yield Vulnerability(**{..., 'matched_at': matched_at})
    # same for Exploit objects
```

## Data Flow

```text
nmap → Technology(match='10.0.0.1:80', product='Apache httpd', version='2.4.50')
       Technology(match='10.0.0.2:80', product='Apache httpd', version='2.4.50')
       Technology(match='10.0.0.3:80', product='nginx', version='1.21.0')

extractor (group_by: '{product} {version}')
  → ['10.0.0.1:80,10.0.0.2:80~Apache httpd 2.4.50', '10.0.0.3:80~nginx 1.21.0']

search_vulns task #1  input: '10.0.0.1:80,10.0.0.2:80~Apache httpd 2.4.50'
  before_init: matched_at='10.0.0.1:80,10.0.0.2:80', inputs[0]='Apache httpd 2.4.50'
  on_json_loaded (CVE-2021-41773):
    → Vulnerability(matched_at='10.0.0.1:80', id='CVE-2021-41773')
    → Vulnerability(matched_at='10.0.0.2:80', id='CVE-2021-41773')

search_vulns task #2  input: '10.0.0.3:80~nginx 1.21.0'
  before_init: matched_at='10.0.0.3:80', inputs[0]='nginx 1.21.0'
  on_json_loaded (CVE-2021-23017):
    → Vulnerability(matched_at='10.0.0.3:80', id='CVE-2021-23017')
```

## Compatibility

- **Sync mode:** no change — extractor grouping happens before the task runs, task receives
  pre-grouped inputs.
- **Celery mode:** same — inputs are computed by `run_extractors` before dispatch; each grouped
  string is one Celery task (one per unique service).
- **`input_chunk_size = 1` preserved:** each grouped input is still one atomic unit; Celery
  chunking still works naturally if the grouped list is large.
- **Backward compatible:** `group_by` is optional on any extractor; existing YAML configs that
  omit it behave identically to today.
- **`searchsploit` benefits for free** by adding `group_by` to its extractor too.

## Files Changed

| File | Change |
|------|--------|
| `secator/runners/_helpers.py` | Add `group_by` to `parse_extractor` + `process_extractor` |
| `secator/configs/workflows/host_recon.yaml` | Add `group_by` to search_vulns + searchsploit tech extractor |
| `secator/tasks/search_vulns.py` | Fan out Vulnerability/Exploit per matched_at host in `on_json_loaded` |

## Testing

- Unit test: `process_extractor` with `group_by` field produces correctly grouped strings
- Unit test: `search_vulns.before_init` handles comma-separated matched_at
- Unit test: `search_vulns.on_json_loaded` emits N Vulnerability objects for N hosts
- Integration test: `host_recon` workflow produces correct Vulnerability objects with per-host
  `matched_at` when multiple hosts share the same service/version
