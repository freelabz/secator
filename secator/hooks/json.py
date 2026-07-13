# secator/hooks/json.py
#
# Live JSON *driver* (not the end-of-run JSON exporter).
#
# It mirrors the mongodb/sqlite drivers but persists to the local filesystem:
# every runner writes/updates its OWN ``report.json`` inside its
# ``runner.reports_folder`` AS results are produced (on_item) and as its status
# changes (on_init/on_start/on_interval/on_end). The file format
# (``{"info": {...}, "results": {type: [items]}}``) is byte-compatible with what
# the JSON exporter emits and with what the ``local`` query backend
# (``secator/query/json.py``) already reads — so a run driven with
# ``--driver json`` is queryable *mid-run*, not just at the end.
#
# Concurrency (the crux):
#   Results are produced by many workers writing the report tree at once.
#     - prefork pool  -> separate OS processes (separate memory)
#     - gevent pool   -> greenlets in one process (cooperative)
#   Sharding does most of the work: each runner owns its own report.json, so two
#   *different* runners never touch the same file. The remaining hazard is two
#   writers hitting the SAME file (a redelivered task, or a flush racing another).
#   Every write goes through ``atomic_json`` (secator.utils): a locked
#   read-modify-write with an atomic swap, correct under both pools. See that
#   function's docstring for the layered-lock details.
#
# Batched writes (why on_item does NOT touch disk):
#   The worker pool is gevent (definitions.py). A file write + os.fsync is a
#   BLOCKING syscall and gevent only monkey-patches sockets, so it CANNOT yield
#   on it — a task emitting many findings would stall the hub on every finding,
#   monopolize the worker, and serialize concurrent tasks (also O(N^2) per
#   runner). So a chatty FINDING (Url/Port/... — the high-volume output) only gets
#   APPENDED to a small in-memory per-runner buffer (O(1), no syscall); the buffer
#   is flushed to report.json in ONE atomic_json write on on_interval (periodic,
#   throttled by backend_update_frequency) and on_end (final — everything persists).
#   mongodb/sqlite keep their per-finding upserts (O(1) network I/O that yields).
#
#   EXECUTION types (Error/Target/Info/Warning/Progress/State) are written
#   IMMEDIATELY, not buffered: they are low-volume (no stall risk) AND the runner's
#   own store-view reads them back synchronously in the same task — self_errors,
#   self_results, and the scope-target extractor all QUERY the store right after
#   add_result(), a read-after-write the buffer would otherwise break. ponytail:
#   split by finding-vs-execution, not per-type; revisit only if some execution
#   type ever becomes chatty (Progress is already throttled upstream).
#
# ponytail: no `on_build` PENDING placeholder (mongodb/sqlite mint one so the UI
# tree shows not-yet-run children). Locally the query backend discovers runners
# by walking report dirs, so a child simply appears once it starts. Add on_build
# if a live "pending children" view is needed.

import uuid
from pathlib import Path
from time import time

from secator.output_types import FINDING_TYPES, is_output_type
from secator.runners import Scan, Task, Workflow
from secator.utils import atomic_json, debug

# Names of the high-volume finding types that get buffered (execution types write
# through immediately — see module docstring). Name-based like is_output_type, so a
# module reload / autoreload can't break it via class identity.
_FINDING_TYPE_NAMES = {t.get_name() for t in FINDING_TYPES}

# Per-report write buffers of UNFLUSHED findings, keyed by report-path string
# (module-level like utils._path_locks — NOT a runner attribute, which would get
# pickled to Celery). Shape: {path: {_type: {_uuid: record}}}. Single-owner per
# runner (one runner runs in one worker), so plain dict ops are safe: under gevent
# they don't yield mid-statement, under prefork each process has its own memory.
# ponytail: entries are never evicted (like _path_locks); harmless, a runner's
# buffer is tiny and cleared on every flush.
_write_buffers = {}


def _empty_report():
	return {'info': {}, 'results': {}}


def _report_path(runner):
	return Path(runner.reports_folder) / 'report.json'


def update_runner(self):
	"""Persist the runner's own info block into its report.json (on_init/on_start). The {type}_id is
	minted by the runner core (Runner.__init__); json keys its report by reports_folder, not the id."""
	info = self.toDict()
	path = _report_path(self)
	with atomic_json(path, default=_empty_report) as data:
		data['info'] = info
	debug(f'wrote runner info to {path}', sub='hooks.json', verbose=True)


def _upsert(bucket, index, uid, record):
	"""Upsert a record into a results bucket by uuid (index maps uuid -> position)."""
	if uid in index:
		bucket[index[uid]] = record
	else:
		index[uid] = len(bucket)
		bucket.append(record)


def update_finding(self, item):
	"""Persist an item to this runner's report.json (on_item/on_duplicate).

	Findings are BUFFERED (O(1), no file I/O) for the next flush_report(); execution
	types are written IMMEDIATELY (rare, and the runner reads them back synchronously
	— see module docstring). Assigns a stable uuid; repeated updates of the same
	finding collapse in the buffer (keyed by uuid).
	"""
	if not is_output_type(item):
		return item
	if not item._uuid:
		item._uuid = str(uuid.uuid4())
	record = item.toDict()
	record['_uuid'] = item._uuid
	if item._type in _FINDING_TYPE_NAMES:
		buf = _write_buffers.setdefault(str(_report_path(self)), {})
		buf.setdefault(item._type, {})[item._uuid] = record
		return item
	# Execution type: write through now (low-volume, read-after-write sensitive).
	with atomic_json(_report_path(self), default=_empty_report) as data:
		bucket = data.setdefault('results', {}).setdefault(item._type, [])
		_upsert(bucket, {r.get('_uuid'): i for i, r in enumerate(bucket)}, item._uuid, record)
	return item


def flush_report(self):
	"""Write buffered findings + current info to report.json in ONE atomic_json write.

	Runs on on_interval (throttled by backend_update_frequency via last_updated_db,
	so periodic not per-finding) and on_end (final). Merges the buffer into the
	file's results upserting by uuid, writes the info block, clears the buffer.
	On write failure the buffer is retained (findings survive to the next flush).
	"""
	path = _report_path(self)
	buf = _write_buffers.get(str(path))
	info = self.toDict()
	with atomic_json(path, default=_empty_report) as data:
		data['info'] = info
		if buf:
			results = data.setdefault('results', {})
			for _type, records in buf.items():
				bucket = results.setdefault(_type, [])
				index = {r.get('_uuid'): i for i, r in enumerate(bucket)}
				for uid, record in records.items():
					_upsert(bucket, index, uid, record)
	if buf:
		buf.clear()  # only reached on a clean atomic_json write (raise skips it)
	self.last_updated_db = time()  # enable on_interval throttling (mongodb parity)
	debug(f'flushed report to {path}', sub='hooks.json', verbose=True)


HOOKS = {
	Scan: {
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_item': [update_finding],
		'on_interval': [flush_report],
		'on_duplicate': [update_finding],
		'on_end': [flush_report],
	},
	Workflow: {
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_item': [update_finding],
		'on_interval': [flush_report],
		'on_duplicate': [update_finding],
		'on_end': [flush_report],
	},
	Task: {
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_item': [update_finding],
		'on_duplicate': [update_finding],
		'on_interval': [flush_report],
		'on_end': [flush_report],
	},
}
