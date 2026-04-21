import json
from pathlib import Path
from time import time

from secator.output_types import FINDING_TYPES
from secator.runners import Scan, Task, Workflow
from secator.serializers.dataclass import DataclassEncoder
from secator.utils import debug


def _get_meta_path(runner):
	return Path(runner.reports_folder) / 'report.meta.json'


def _get_sidecar_path(runner, type_name):
	return Path(runner.reports_folder) / f'report.{type_name}.jsonl'


def _get_report_path(runner):
	return Path(runner.reports_folder) / 'report.json'


def _cleanup_sidecars(runner):
	meta_path = _get_meta_path(runner)
	if meta_path.exists():
		try:
			meta_path.unlink()
		except Exception as e:
			debug(f'Error removing meta file: {e}', sub='hooks.json')
	for output_type in FINDING_TYPES:
		sidecar_path = _get_sidecar_path(runner, output_type.get_name())
		if sidecar_path.exists():
			try:
				sidecar_path.unlink()
			except Exception as e:
				debug(f'Error removing sidecar {sidecar_path}: {e}', sub='hooks.json')


def update_runner(self):
	"""Write runner metadata to report.meta.json."""
	meta_path = _get_meta_path(self)
	try:
		with open(meta_path, 'w') as f:
			json.dump(self.toDict(), f, cls=DataclassEncoder)
		self.last_updated_db = time()
		debug(f'Updated runner meta at {meta_path}', sub='hooks.json')
	except Exception as e:
		debug(f'Error writing runner meta: {e}', sub='hooks.json')


def update_item(self, item):
	"""Append item to per-type sidecar .jsonl file (O(1), no reads)."""
	if type(item) not in FINDING_TYPES:
		return item
	sidecar_path = _get_sidecar_path(self, item._type)
	try:
		with open(sidecar_path, 'a') as f:
			json.dump(item.toDict(), f, cls=DataclassEncoder)
			f.write('\n')
	except Exception as e:
		debug(f'Error writing item to sidecar: {e}', sub='hooks.json')
	return item


def finalize_task_report(self):
	"""Merge per-type .jsonl sidecars into report.json, then clean up."""
	report_path = _get_report_path(self)
	info = self.toDict()
	results = {}
	for output_type in FINDING_TYPES:
		type_name = output_type.get_name()
		sidecar_path = _get_sidecar_path(self, type_name)
		items = []
		if sidecar_path.exists():
			try:
				with open(sidecar_path, 'r') as f:
					for line in f:
						line = line.strip()
						if line:
							items.append(json.loads(line))
			except Exception as e:
				debug(f'Error reading sidecar {sidecar_path}: {e}', sub='hooks.json')
		results[type_name] = items
	try:
		with open(report_path, 'w') as f:
			json.dump({'info': info, 'results': results}, f, cls=DataclassEncoder, indent=2)
		debug(f'Wrote final JSON report to {report_path}', sub='hooks.json')
	except Exception as e:
		debug(f'Error writing final report: {e}', sub='hooks.json')
	_cleanup_sidecars(self)


def finalize_composite_report(self):
	"""Write report.json from in-memory results for Workflow/Scan runners."""
	report_path = _get_report_path(self)
	info = self.toDict()
	results = {}
	for output_type in FINDING_TYPES:
		type_name = output_type.get_name()
		results[type_name] = [
			item.toDict() if hasattr(item, 'toDict') else item
			for item in self.results
			if getattr(item, '_type', None) == type_name
		]
	try:
		with open(report_path, 'w') as f:
			json.dump({'info': info, 'results': results}, f, cls=DataclassEncoder, indent=2)
		debug(f'Wrote final JSON report to {report_path}', sub='hooks.json')
	except Exception as e:
		debug(f'Error writing final report: {e}', sub='hooks.json')
	meta_path = _get_meta_path(self)
	if meta_path.exists():
		try:
			meta_path.unlink()
		except Exception as e:
			debug(f'Error removing meta file: {e}', sub='hooks.json')


HOOKS = {
	Scan: {
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_interval': [update_runner],
		'on_end': [finalize_composite_report],
	},
	Workflow: {
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_interval': [update_runner],
		'on_end': [finalize_composite_report],
	},
	Task: {
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_item': [update_item],
		'on_duplicate': [update_item],
		'on_interval': [update_runner],
		'on_end': [finalize_task_report],
	}
}
