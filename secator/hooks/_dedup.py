# secator/hooks/_dedup.py


def _is_unset(field, value):
	"""Return True if `value` should be treated as "empty" for copy-forward purposes.

	For most fields, emptiness is the generic falsy check (`not value`). The `status`
	field (Vulnerability) is special: its default value `'NEW'` is truthy but means
	"untouched", so we treat `''` / `None` / `'NEW'` as unset. This lets a prior
	`ACKNOWLEDGED` / `FIXED` status carry forward onto a re-found main whose status is
	still the default `'NEW'`, while a never-touched vuln stays `'NEW'`.
	"""
	if field == 'status':
		return not value or str(value).strip().upper() == 'NEW'
	return not value


def compute_duplicate_updates(workspace_findings, untagged_findings, copy_fields=None):
	"""Compute duplicate-tagging updates for a set of findings (backend-agnostic).

	Args:
		workspace_findings (list): Already-tagged, non-duplicate findings in the workspace
			(loaded OutputType objects).
		untagged_findings (list): Newly-seen / untagged findings to evaluate.
		copy_fields (list): Field names to copy from a previous "main" finding onto the
			new main finding when the new value is empty.

	Returns:
		dict: uuid -> update dict (fields to set), where each update may contain
		'_related', '_context.workspace_duplicate', '_tagged' and copied fields.
	"""
	copy_fields = copy_fields or []
	seen = []
	db_updates = {}

	for item in untagged_findings:
		if item._uuid in seen:
			continue

		duplicate_ids = [_._uuid for _ in untagged_findings if _ == item and _._uuid != item._uuid]
		seen.extend(duplicate_ids)

		duplicate_ws = [_ for _ in workspace_findings if _ == item and _._uuid != item._uuid]

		# Copy selected fields from the previous "main" finding when current value is empty.
		copied_fields = {}
		for previous_item in duplicate_ws:
			for field in copy_fields:
				if not hasattr(previous_item, field):
					continue
				value_prev = getattr(previous_item, field)
				# Nothing meaningful to carry forward (handles `status='NEW'` as unset too).
				if _is_unset(field, value_prev):
					continue
				value_curr = getattr(item, field, None)
				# Copy only onto an "empty" current value; for `status`, `'NEW'` counts as empty.
				if _is_unset(field, value_curr) and field not in copied_fields:
					copied_fields[field] = value_prev

		related_ids = []
		if duplicate_ws:
			duplicate_ids.extend([_._uuid for _ in duplicate_ws])
			for related in duplicate_ws:
				related_ids.extend(related._related)

		db_updates[item._uuid] = {
			**copied_fields,
			'_related': duplicate_ids + related_ids,
			'_context.workspace_duplicate': False,
			'_tagged': True,
		}
		for uuid_ in duplicate_ids:
			db_updates[uuid_] = {
				'_context.workspace_duplicate': True,
				'_tagged': True,
			}
	return db_updates
