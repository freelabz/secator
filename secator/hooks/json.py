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

import orjson
from pathlib import Path

from secator.output_types import is_output_type, Info
from secator.rich import console
from secator.runners import Scan, Task, Workflow
from secator.utils import append_ndjson, atomic_json, debug


def _empty_report():
	return {'info': {}, 'results': {}}


def _report_path(runner):
	return Path(runner.reports_folder) / 'report.json'


def _ndjson_path(runner):
	return Path(runner.reports_folder) / 'results.ndjson'


def announce_report(self):
	"""At run end, announce where the live JSON report was written — mirrors the former JSON
	exporter's message. Only the top-level runner prints (not every child task), gated by
	``print_reports_message`` like the exporters."""
	if self.has_parent:
		return
	if self.print_reports_message:
		console.print(Info(message=f'JSON report written to {_report_path(self)}'))


def update_runner(self):
	"""Persist the runner's own info block into its report.json (live). The {type}_id is minted by
	the runner core (Runner.__init__); json keys its report by reports_folder, not the id."""
	info = self.toDict()
	path = _report_path(self)
	with atomic_json(path, default=_empty_report) as data:
		data['info'] = info
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
	record = item.toDict()  # _uuid already minted by Runner.add_result before on_item fires
	append_ndjson(_ndjson_path(self), orjson.dumps(record, default=str).decode())
	return item


HOOKS = {
	Scan: {
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_item': [update_finding],
		'on_interval': [update_runner],
		'on_duplicate': [update_finding],
		'on_end': [update_runner, announce_report],
	},
	Workflow: {
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_item': [update_finding],
		'on_interval': [update_runner],
		'on_duplicate': [update_finding],
		'on_end': [update_runner, announce_report],
	},
	Task: {
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_item': [update_finding],
		'on_duplicate': [update_finding],
		'on_interval': [update_runner],
		'on_end': [update_runner, announce_report],
	},
}
