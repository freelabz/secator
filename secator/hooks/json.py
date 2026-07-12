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
#   writers hitting the SAME file (a redelivered task, or update_finding racing
#   update_runner). We make every write a locked read-modify-write with an
#   atomic swap, correct under both pools:
#     1. per-path in-process lock (``threading.Lock``) — gevent monkey-patches
#        threading, so this is greenlet-cooperative under the gevent pool and a
#        real mutex under prefork threads. It serializes same-process writers
#        BEFORE they touch the OS lock, so the blocking flock below is only ever
#        contended across processes (rare), never stalling the gevent hub.
#     2. ``fcntl.flock(LOCK_EX)`` on a stable sidecar ``.lock`` file — mutual
#        exclusion across prefork processes. The lock is a *separate* file (never
#        replaced), so os.replace() below can't pull the locked inode out from
#        under a holder.
#     3. tempfile + ``os.replace`` — atomic on POSIX, so a concurrent reader
#        (e.g. the query backend mid-run) always sees a whole old-or-new file,
#        never a torn write.
#   The lock serializes RMW, so no update is lost; the atomic swap means no
#   reader ever sees corruption.
#
# ponytail: no `on_build` PENDING placeholder (mongodb/sqlite mint one so the UI
# tree shows not-yet-run children). Locally the query backend discovers runners
# by walking report dirs, so a child simply appears once it starts. Add on_build
# if a live "pending children" view is needed.

import fcntl
import json
import os
import tempfile
import threading
import uuid
from pathlib import Path

from secator.output_types import OUTPUT_TYPES
from secator.runners import Scan, Task, Workflow
from secator.utils import debug

# One lock object per report.json path, so same-process writers (greenlets under
# gevent, threads under prefork) serialize before the cross-process flock.
_path_locks = {}
_path_locks_guard = threading.Lock()


def _get_path_lock(path):
	key = str(path)
	lock = _path_locks.get(key)
	if lock is None:
		with _path_locks_guard:
			lock = _path_locks.get(key)
			if lock is None:
				lock = threading.Lock()
				_path_locks[key] = lock
	return lock


def _read_json(path):
	"""Read a report.json, tolerating absence / partial writes.

	os.replace makes torn reads impossible in the normal path; the JSONDecodeError
	guard is belt-and-suspenders for an externally-truncated file.
	"""
	try:
		with open(path, 'r') as f:
			return json.load(f)
	except (FileNotFoundError, json.JSONDecodeError):
		return {'info': {}, 'results': {}}


def _atomic_write(path, data):
	"""Write JSON to a temp file in the same dir, then os.replace() over the target."""
	path = Path(path)
	fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix='.report-', suffix='.json.tmp')
	try:
		with os.fdopen(fd, 'w') as f:
			json.dump(data, f, indent=2, default=str)
			f.flush()
			os.fsync(f.fileno())
		os.replace(tmp, path)
	except BaseException:
		try:
			os.unlink(tmp)
		except OSError:
			pass
		raise


def atomic_json_update(path, mutate):
	"""Concurrency-safe read-modify-write of a report.json.

	Args:
		path (str | Path): report.json path.
		mutate (callable): takes the loaded dict, mutates it in place.

	Safe under both Celery pools (prefork processes + gevent greenlets): see the
	module docstring. Returns the mutated dict.
	"""
	path = Path(path)
	path.parent.mkdir(parents=True, exist_ok=True)
	lock_path = str(path) + '.lock'
	with _get_path_lock(path):                        # (1) in-process (greenlet/thread)
		with open(lock_path, 'w') as lock_fd:
			fcntl.flock(lock_fd, fcntl.LOCK_EX)       # (2) cross-process (prefork)
			try:
				data = _read_json(path)
				if 'results' not in data:
					data['results'] = {}
				if 'info' not in data:
					data['info'] = {}
				mutate(data)
				_atomic_write(path, data)             # (3) atomic swap
				return data
			finally:
				fcntl.flock(lock_fd, fcntl.LOCK_UN)


def _report_path(runner):
	return Path(runner.reports_folder) / 'report.json'


def update_runner(self):
	"""Persist the runner's own info block into its report.json (live)."""
	info = self.toDict()

	def mutate(data):
		data['info'] = info

	path = _report_path(self)
	atomic_json_update(path, mutate)
	debug(f'wrote runner info to {path}', sub='hooks.json', verbose=True)


def update_finding(self, item):
	"""Upsert a single finding into this runner's report.json results (live)."""
	if type(item) not in OUTPUT_TYPES:
		return item
	if not item._uuid:
		item._uuid = str(uuid.uuid4())
	record = item.toDict()
	record['_uuid'] = item._uuid
	_type = item._type

	def mutate(data):
		bucket = data['results'].setdefault(_type, [])
		for i, existing in enumerate(bucket):
			if existing.get('_uuid') == item._uuid:
				bucket[i] = record
				return
		bucket.append(record)

	atomic_json_update(_report_path(self), mutate)
	return item


HOOKS = {
	Scan: {
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_item': [update_finding],
		'on_interval': [update_runner],
		'on_duplicate': [update_finding],
		'on_end': [update_runner],
	},
	Workflow: {
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_item': [update_finding],
		'on_interval': [update_runner],
		'on_duplicate': [update_finding],
		'on_end': [update_runner],
	},
	Task: {
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_item': [update_finding],
		'on_duplicate': [update_finding],
		'on_interval': [update_runner],
		'on_end': [update_runner],
	},
}
