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
# ponytail: no `on_build` PENDING placeholder (mongodb/sqlite mint one so the UI
# tree shows not-yet-run children). Locally the query backend discovers runners
# by walking report dirs, so a child simply appears once it starts. Add on_build
# if a live "pending children" view is needed.

import uuid
from pathlib import Path

from secator.output_types import is_output_type
from secator.runners import Scan, Task, Workflow
from secator.utils import atomic_json, debug


def _empty_report():
	return {'info': {}, 'results': {}}


def _report_path(runner):
	return Path(runner.reports_folder) / 'report.json'


def update_runner(self):
	"""Persist the runner's own info block into its report.json (live). The {type}_id is minted by
	the runner core (Runner.__init__); json keys its report by reports_folder, not the id."""
	info = self.toDict()
	path = _report_path(self)
	with atomic_json(path, default=_empty_report) as data:
		data['info'] = info
	debug(f'wrote runner info to {path}', sub='hooks.json', verbose=True)


def update_finding(self, item):
	"""Upsert a single finding into this runner's report.json results (live)."""
	if not is_output_type(item):
		return item
	if not item._uuid:
		item._uuid = str(uuid.uuid4())
	record = item.toDict()
	record['_uuid'] = item._uuid
	_type = item._type

	with atomic_json(_report_path(self), default=_empty_report) as data:
		bucket = data.setdefault('results', {}).setdefault(_type, [])
		for i, existing in enumerate(bucket):
			if existing.get('_uuid') == item._uuid:
				bucket[i] = record
				break
		else:
			bucket.append(record)
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
