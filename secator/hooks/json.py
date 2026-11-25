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
#   update_runner). Every write goes through ``atomic_json`` (secator.utils): a
#   locked read-modify-write with an atomic swap, correct under both pools. See
#   that function's docstring for the layered-lock details.
#
# ponytail: no `on_build` PENDING placeholder (mongodb/sqlite mint one so clients
# show not-yet-run children). Locally the query backend discovers runners
# by walking report dirs, so a child simply appears once it starts. Add on_build
# if a live "pending children" view is needed.

import orjson
import time
import uuid
from pathlib import Path

from secator.output_types import is_output_type, Info
from secator.rich import console
from secator.runners import Scan, Task, Workflow
from secator.utils import append_ndjson, atomic_json, compact_ndjson, debug, remove_lock_sidecar, remove_lock_sidecars


def _empty_report():
	return {'info': {}, 'results': {}}


def _report_path(runner):
	# Children share the parent's reports_folder, so a workflow/scan and its tasks would otherwise
	# all write the same report.json and clobber each other's info block. Children write a per-child
	# report_<fqn>.json instead. (Reading those back for per-task detail — MongoDB parity — is a
	# parked follow-up; findings still stream to the shared results.ndjson.)
	if runner.has_parent:
		return Path(runner.reports_folder) / f'report_{runner.fqn}.json'
	return Path(runner.reports_folder) / 'report.json'


def _ndjson_path(runner):
	return Path(runner.reports_folder) / 'results.ndjson'


def release_report_lock(self):
	"""Once a runner ended, remove the lock sidecar of its OWN report file.

	Registered on ``on_end`` after ``update_runner``, i.e. after the runner's last write to that
	file. ``on_end`` fires once per runner in every terminal state (success, failure, stop/revoke,
	timeout: the runner's ``mark_completed``). Each report file has a single writer, the runner
	whose ``fqn`` names it: a chunk writes ``report_<task>_<n>.json``, and a chunked task's own
	``report_<task>.json`` is written by that task alone, whose ``on_end`` runs in the chord
	callback after all its chunks. Shared files (``results.ndjson``, written by every runner of the
	run) keep their lock until the end of the top-level run (``finalize_store``).

	Best-effort: a sidecar that is missing here (e.g. on another host) is skipped. A later writer
	just recreates the sidecar (see ``secator.utils._file_lock``)."""
	try:
		remove_lock_sidecar(_report_path(self))
	except Exception as e:  # noqa: BLE001 — housekeeping must never fail a finished runner
		debug(f'report lock cleanup failed: {e}', sub='hooks.json')


def finalize_store(self):
	"""At the end of a top-level run, compact its findings store and remove its lock sidecars.

	Registered on ``on_run_end``, which fires once for the whole run, after every runner of it
	wrote its last record (children complete before their parent). Compaction drops superseded
	versions of updated findings (see ``secator.utils.compact_ndjson``) and the ``*.lock``
	sidecars of the run's report dir are removed. Both are safe against a later writer (e.g. a
	finding updated afterwards): compaction holds the append lock, and a removed sidecar is just
	recreated (see ``secator.utils._file_lock``). Removing every sidecar of the dir also catches
	those a runner left behind when its process was killed before its ``on_end``. Best-effort and
	never fails the run."""
	folder = Path(self.reports_folder)
	try:
		compacted = compact_ndjson(folder / 'results.ndjson')
		removed = remove_lock_sidecars(folder)
		debug(f'store finalized: compacted={compacted} lock sidecars removed={removed}', sub='hooks.json')
	except Exception as e:  # noqa: BLE001 — housekeeping must never fail a finished run
		debug(f'store finalization failed: {e}', sub='hooks.json')


def announce_report(self):
	"""At run end, announce where the live JSON report was written — mirrors the former JSON
	exporter's message. Registered on ``on_run_end``, so only the top-level runner prints (not every
	child task), gated by ``print_reports_message`` like the exporters."""
	if self.print_reports_message:
		console.print(Info(message=f'JSON report written to {_report_path(self)}'))


def update_runner(self):
	"""Persist the runner's own info block into its report.json (live). The {type}_id is minted by
	the runner core (Runner.__init__); json keys its report by reports_folder, not the id."""
	info = self.toDict()
	path = _report_path(self)
	start_time = time.time()
	with atomic_json(path, default=_empty_report) as data:
		data['info'] = info
	self.last_updated_db = start_time
	debug(f'wrote runner info to {path}', sub='hooks.json', verbose=True)


def update_finding(self, item):
	"""Append a single finding to this runner's results.ndjson (live, O(1)).

	Append-only. Own-emit dedup is the runner core's in-memory self.uuids (add_result skips an
	already-seen _uuid before on_item fires), so the common path appends each finding once and no
	in-file scan is needed here. A redelivered/racing writer that does append a second line with the
	same _uuid is resolved last-wins by the query backend on read.
	"""
	if not is_output_type(item):
		return item
	# add_result mints _uuid on the normal path, but update_finding can also be called on
	# items that never routed through it (the on_item hook invoked directly, re-emits) — mint
	# defensively so every appended record carries a stable _uuid for last-wins dedup on read.
	if not item._uuid:
		item._uuid = str(uuid.uuid4())
	record = item.toDict()
	record['_uuid'] = item._uuid
	# A suggestion is not a finding: keep it out of the results the query backend reads.
	path = _ndjson_path(self).with_name('suggestions.ndjson') if item._type == 'suggestion' else _ndjson_path(self)
	append_ndjson(path, orjson.dumps(record, default=str).decode())
	return item


HOOKS = {
	Scan: {
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_item': [update_finding],
		'on_interval': [update_runner],
		'on_end': [update_runner, release_report_lock],
		'on_run_end': [finalize_store, announce_report],
	},
	Workflow: {
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_item': [update_finding],
		'on_interval': [update_runner],
		'on_end': [update_runner, release_report_lock],
		'on_run_end': [finalize_store, announce_report],
	},
	Task: {
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_item': [update_finding],
		'on_interval': [update_runner],
		'on_end': [update_runner, release_report_lock],
		'on_run_end': [finalize_store, announce_report],
	},
}
