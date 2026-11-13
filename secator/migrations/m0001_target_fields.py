"""Backfill the derived ``target`` / ``target_host`` fields on findings stored before they existed."""
from secator.output_types import FINDING_TYPES

ID = '0001_target_fields'
DESCRIPTION = 'Backfill target / target_host on findings'

_TYPES = {cls.get_name(): cls for cls in FINDING_TYPES}
QUERY = {
	'_type': {'$in': list(_TYPES)},
	'$or': [{'target': {'$exists': False}}, {'target_host': {'$exists': False}}],
}


def compute(doc):
	"""Return the target fields to set on a stored finding, or None if it already has them."""
	if doc.get('target') is not None and doc.get('target_host') is not None:
		return None
	target, target_host = _TYPES[doc['_type']].compute_target(doc)
	return {'target': target, 'target_host': target_host}


def run(backend, dry_run=True):
	if not dry_run:
		backend.ensure_index(['_context.workspace_id', 'target_host'])
	return backend.bulk_update(QUERY, compute, dry_run=dry_run)
