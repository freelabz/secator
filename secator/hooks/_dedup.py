# secator/hooks/_dedup.py


def build_baseline_index(findings, copy_fields=None):
	"""Fold already-tagged workspace findings into a compact, memory-bounded index.

	The baseline (existing non-duplicate findings in a workspace) can be huge — tens
	to hundreds of thousands of docs. `compute_duplicate_updates` only ever needs, per
	equality group: the matching findings' uuids, the union of their `_related`, and the
	first non-empty value of each `copy_field`. So we fold each finding into that tiny
	aggregate keyed by its `_compare_key()` (which already encodes `_type`) and drop the
	full object — peak memory is O(distinct keys × small payload) instead of O(full docs).

	`findings` may be any iterable (list or a streaming generator over a DB cursor), so
	callers can avoid ever materializing the full baseline in memory.

	Args:
		findings (iterable): Loaded OutputType baseline findings.
		copy_fields (list): Field names whose first non-empty baseline value to retain.

	Returns:
		dict: compare_key -> {'uuids': [...], 'related': [...], 'copy': {field: value}}.
	"""
	copy_fields = copy_fields or []
	index = {}
	for item in findings:
		key = item._compare_key()
		entry = index.get(key)
		if entry is None:
			entry = {'uuids': [], 'related': [], 'copy': {}}
			index[key] = entry
		entry['uuids'].append(item._uuid)
		if item._related:
			entry['related'].extend(item._related)
		for field in copy_fields:
			if field in entry['copy']:
				continue
			value = getattr(item, field, None)
			if value:
				entry['copy'][field] = value
	return index


def compute_duplicate_updates(workspace_findings, untagged_findings, copy_fields=None, baseline_index=None):
	"""Compute duplicate-tagging updates for a set of findings (backend-agnostic).

	Args:
		workspace_findings (list): Already-tagged, non-duplicate findings in the workspace
			(loaded OutputType objects). Ignored when `baseline_index` is provided.
		untagged_findings (list): Newly-seen / untagged findings to evaluate.
		copy_fields (list): Field names to copy from a previous "main" finding onto the
			new main finding when the new value is empty.
		baseline_index (dict): Optional pre-built baseline index (see `build_baseline_index`).
			Lets memory-sensitive callers stream the baseline instead of passing a full list.

	Returns:
		dict: uuid -> update dict (fields to set), where each update may contain
		'_related', '_context.workspace_duplicate', '_tagged' and copied fields.
	"""
	copy_fields = copy_fields or []
	if baseline_index is None:
		baseline_index = build_baseline_index(workspace_findings, copy_fields)
	seen = []
	db_updates = {}

	for item in untagged_findings:
		if item._uuid in seen:
			continue

		duplicate_ids = [_._uuid for _ in untagged_findings if _ == item and _._uuid != item._uuid]
		seen.extend(duplicate_ids)

		copied_fields = {}
		related_ids = []
		entry = baseline_index.get(item._compare_key())
		if entry:
			ws_uuids = [uuid_ for uuid_ in entry['uuids'] if uuid_ != item._uuid]
			if ws_uuids:
				duplicate_ids.extend(ws_uuids)
				related_ids.extend(entry['related'])
				# Copy selected fields from the previous "main" finding when current value is empty.
				for field in copy_fields:
					value_prev = entry['copy'].get(field)
					if not value_prev:
						continue
					value_curr = getattr(item, field, None)
					if not value_curr and field not in copied_fields:
						copied_fields[field] = value_prev

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
