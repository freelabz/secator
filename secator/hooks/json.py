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
#   runner). So on_item only APPENDS the finding to a small in-memory per-runner
#   buffer (O(1), no syscall, yields nothing to block on); the buffer is flushed
#   to report.json in ONE atomic_json write on on_interval (periodic, throttled by
#   backend_update_frequency) and on_end (final — guarantees everything persists).
#   mongodb/sqlite keep their per-finding upserts (O(1) network I/O that yields).
#
# ponytail: no `on_build` PENDING placeholder (mongodb/sqlite mint one so the UI
# tree shows not-yet-run children). Locally the query backend discovers runners
# by walking report dirs, so a child simply appears once it starts. Add on_build
# if a live "pending children" view is needed.

import uuid
from pathlib import Path
from time import time

from secator.output_types import OUTPUT_TYPES
from secator.runners import Scan, Task, Workflow
from secator.utils import atomic_json, debug

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
	"""Persist the runner's own info block into its report.json (on_init/on_start)."""
	info = self.toDict()
	path = _report_path(self)
	with atomic_json(path, default=_empty_report) as data:
		data['info'] = info
	debug(f'wrote runner info to {path}', sub='hooks.json', verbose=True)


def update_finding(self, item):
	"""Buffer a finding for the next flush (on_item/on_duplicate). O(1), no file I/O.

	Assigns a stable uuid and stashes the record in the runner's in-memory buffer,
	keyed by uuid so repeated updates of the same finding collapse. Persisted by
	flush_report() on the next on_interval / on_end.
	"""
	if type(item) not in OUTPUT_TYPES:
		return item
	if not item._uuid:
		item._uuid = str(uuid.uuid4())
	record = item.toDict()
	record['_uuid'] = item._uuid
	buf = _write_buffers.setdefault(str(_report_path(self)), {})
	buf.setdefault(item._type, {})[item._uuid] = record
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
					if uid in index:
						bucket[index[uid]] = record
					else:
						index[uid] = len(bucket)
						bucket.append(record)
	if buf:
		buf.clear()  # only reached on a clean atomic_json write (raise skips it)
	self.last_updated_db = time()  # enable on_interval throttling (mongodb parity)
	debug(f'flushed report to {path}', sub='hooks.json', verbose=True)


HOOKS = {
	Scan: {
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_interval': [flush_report],
		'on_duplicate': [update_finding],
		'on_end': [flush_report],
	},
	Workflow: {
		'on_init': [update_runner],
		'on_start': [update_runner],
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
