"""Set the derived ``target`` field on stored findings (missing on findings stored before it existed)."""
from secator.output_types import FINDING_TYPES

DESCRIPTION = 'Backfill target on findings'
TYPES = {cls.get_name(): cls for cls in FINDING_TYPES if cls._target_fields}


def _scopes(backend):
	"""Yield once per store scope: each runner folder on the json store, the whole store otherwise."""
	if backend.name != 'json':
		yield
		return
	for runner_dir in sorted(backend.reports_dir.glob('*/*/*')):
		if runner_dir.is_dir() and runner_dir.parent.name in ('tasks', 'workflows', 'scans'):
			backend.context = {'report_dir': str(runner_dir)}
			yield


def run(backend, apply=False):
	"""Set ``target`` where the stored value differs from the computed one (all workspaces, false positives included).

	Returns:
		tuple[int, int]: Matched findings, and findings changed (or to change on a dry run).
	"""
	matched = changed = 0
	for _ in _scopes(backend):
		updates = {}
		for batch in backend._execute_iterate({'_type': {'$in': list(TYPES)}}):
			for doc in batch:
				matched += 1
				target = TYPES[doc['_type']].compute_target(doc)
				if target != doc.get('target', '') and doc.get('_uuid'):
					updates[doc['_uuid']] = target
		changed += len(updates)
		if apply:
			for uuid, target in updates.items():
				backend._execute_update({'_uuid': uuid}, {'$set': {'target': target}})
	return matched, changed
