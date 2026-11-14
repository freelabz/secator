"""Backfill the derived ``target`` field on findings stored before it existed."""
from secator.output_types import FINDING_TYPES

ID = '0001_target_fields'
DESCRIPTION = 'Backfill target on findings'

_TYPES = {cls.get_name(): cls for cls in FINDING_TYPES}
QUERY = {'_type': {'$in': list(_TYPES)}, 'target': {'$exists': False}}


def compute(doc):
	"""Return the target to set on a stored finding, or None if it already has one."""
	if doc.get('target') is not None:
		return None
	return {'target': _TYPES[doc['_type']].compute_target(doc)}


def run(backend, dry_run=True):
	return backend.bulk_update(QUERY, compute, dry_run=dry_run)
