# JSON Driver NDJSON Store — Design

**Status:** design (candidate replacement for the `feat/json-driver` per-item write path)
**Date:** 2026-07-16
**Branch:** `feat/json-driver-ndjson` (off `feat/drop-chain-payload`)

## Goal

Make the local JSON store's write path **O(N)** instead of **O(N²)**, so a runner
that emits N findings persists them in linear time — matching the mongodb/sqlite
drivers — without changing the completed-report on-disk format or the CLI.

## Problem

`hooks/json.py::update_finding` runs on **every** emitted finding and, via
`atomic_json`, does a full **read-modify-write of the entire `report.json`**:

```python
with atomic_json(_report_path(self)) as data:      # 1. read + parse WHOLE file    O(k)
    bucket = data['results'].setdefault(_type, [])
    for i, existing in enumerate(bucket):          # 2. linear _uuid dedup scan     O(k)
        if existing['_uuid'] == item._uuid: ...
    else: bucket.append(record)
    # atomic_json exit: _atomic_write -> tempfile + fsync + os.replace WHOLE file   O(k)
```

Finding #k costs O(k) three ways (parse, dedup scan, rewrite) plus an **fsync per
item**. Summed over N → **O(N²)** CPU + IO. The mongodb driver's `update_finding`
is one indexed `insert_one`/`update_one` → O(1)/item → O(N) total.

**Measured** (memray harness, fan-in workload): at 10k the json-driver runner
does not complete (~4 findings/sec, ~40 min projected); mongodb completes in
seconds. This is the regression that forced the mongodb store for #1312's
benchmarks.

## Design: append-only NDJSON sidecar

Each runner keeps `report.json` for the **info block only** and writes findings to
a sibling append-only **`results.ndjson`** in the same report dir (one finding =
one JSON line). Reads assemble the same logical `{type: [items]}` view from the
ndjson; completed/old reports without an ndjson fall back to today's
`report.json['results']`.

```
<reports>/<ws>/<runner_type>/<n>/
    report.json      # {"info": {...}}           <- info only, rewritten on status change
    results.ndjson   # {record}\n{record}\n ...  <- append-only, one line per finding
```

### Write path — `hooks/json.py`

`update_finding(self, item)`:
- Serialize the record once (`item.toDict()` + `_uuid`), `json.dumps` to a single
  line (no embedded newlines — enforce `ensure_ascii` or escape).
- Append under the **existing `flock`** (a record can exceed `PIPE_BUF` = 4 KB, so
  a bare concurrent `write()` is not atomic): open `results.ndjson` in append mode,
  write `line + "\n"`, flush. The locked section is now "append one line," not
  "parse + rewrite the file," so contention across the gevent/prefork pools
  collapses. No fsync per item (durability of the live store is not required; a
  crash is handled by torn-line tolerance on read).
- **Drop the in-file dedup scan** — the runner's in-memory `self.uuids` already
  guards own-emit dedup. Re-emitted findings (`on_duplicate`, enrichment) append a
  **second line** with the same `_uuid`; the reader resolves last-wins (below).

`update_runner(self)` (info block, on status change) is unchanged in shape but now
writes an **info-only** `report.json` (small, bounded, separate file from the
ndjson — the two never clobber each other). Keep `atomic_json` here.

`atomic_json` itself is unchanged and still used for `report.json`. A small helper
`append_ndjson(path, line)` encapsulates the locked append.

### Read path — `query/json.py::_read_report_dir` (the one seam)

```python
def _read_report_dir(self, report_dir, runner_type_singular, findings):
    ndjson = report_dir / 'results.ndjson'
    if ndjson.exists():
        by_uuid = {}                                  # last-wins dedup
        with open(ndjson) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue                          # torn final line -> skip (crash tolerance)
                by_uuid[rec.get('_uuid') or id(rec)] = rec
        items = list(by_uuid.values())
    else:                                             # completed/pre-change report
        report_file = report_dir / 'report.json'
        if not report_file.exists():
            return
        try:
            data = json.load(open(report_file))
        except (json.JSONDecodeError, IOError):
            return
        items = [it for lst in data.get('results', {}).values()
                 if isinstance(lst, list) for it in lst]
    runner_id = report_dir.name
    for item in items:
        item.setdefault('_context', {}).setdefault(f'{runner_type_singular}_id', runner_id)
    findings.extend(items)
```

The rest of `query/json.py` (`_load_from_files`, run-scoped vs workspace-scan,
`_execute_search`) is unchanged: it already materializes a `findings` list, so
last-wins dedup adds a dict of the same order of memory it already uses.

`report.py` (the `Report` class) already builds `data['results']` from the query
engine (`StreamView`/`engine.search`), so **every exporter and `report show` is
already engine-mediated** and inherits the fix with no change.

### Backward compatibility

- **No `on_end` materialization** (decided): completed reports keep their
  `results.ndjson`; the reader handles it for live and completed alike. Pre-change
  reports (no ndjson) fall back to `report.json['results']`.
- **UI / API: out of scope** — both use the mongodb driver and never read the JSON
  store.
- **Direct `json.load(report.json)` in `cli.py`** (approx lines 1510, 1763, 1871):
  audit each. Those reading the **info** block are unaffected (info stays in
  `report.json`). Any reading `data.get('results')` directly must route through the
  query engine or read `results.ndjson` — enumerate and fix in the plan.

### Concurrency & crash safety

- **Concurrency:** appends stay under `flock` (cross-process) + the in-process path
  lock, exactly as `atomic_json` does today; only the critical section shrinks.
  Multiple runners write different files (sharded by report dir) as before; the
  residual same-file hazard (redelivered task, `update_finding` vs re-emit) is
  covered by the lock.
- **Crash safety:** a crash mid-append can leave a torn final line. The reader
  skips any line that fails `json.loads` — no `.len` sidecar, no repair pass. This
  is the property that makes NDJSON simpler than bracket-patching a JSON array.

### Non-goals

- Read-side streaming/memory (json_stream): the reader still materializes a
  `findings` list, same as today. Streaming reads are a separate, optional follow-up.
- Changing the mongodb/sqlite drivers or the completed-report JSON artifact format.
- Cross-run/workspace-scan performance (unchanged; still a dir walk).

## Open audit item

`runners/_base.py` (~L384–392) documents a local-json "fan-in re-persists every
descendant finding up into each ancestor's `report.json`, re-tagged" hot path.
Confirm whether this re-persistence still occurs in the drop-chain stack and, if
so, that it appends to each ancestor's `results.ndjson` (O(total) per ancestor
level, acceptable) rather than depending on the old dict structure. Flagged
low-risk by the maintainer; verify during implementation.

## Testing

- **Unit (`tests/unit`):**
  - append→read round-trip: N findings appended, reader returns N with fields intact.
  - torn-final-line: truncate the last line mid-record, reader returns N−1, no raise.
  - last-wins dedup: same `_uuid` appended twice, reader returns the later record.
  - old-format fallback: a report dir with only `report.json` (dict results) reads
    identically to today.
- **Concurrency:** M greenlets + prefork children appending to one `results.ndjson`
  under load; assert no corrupt lines and exact expected count.
- **Perf (acceptance bar):** the memray matrix `sync-json` / `worker-json` cells go
  from **O(N²) DNF → O(N) completing at 1M**, with peak RAM and walltime in the same
  order as the mongodb cells. This is the gate for "checks out."

## Acceptance

Land only if: all unit + concurrency tests pass; the json-driver benchmark cells
complete at 1M with linear-ish scaling; and no direct-reader regression in the
`cli.py` audit. Then evaluate as a replacement for the `feat/json-driver` write path.
