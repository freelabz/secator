import unittest

from secator.hooks._dedup import compute_duplicate_updates
from secator.output_types import Vulnerability


def _vuln(uuid, status='NEW', verified=False, **kwargs):
	return Vulnerability(
		name='CVE-2025-53020',
		id='CVE-2025-53020',
		matched_at='host:80',
		status=status,
		verified=verified,
		_uuid=uuid,
		**kwargs,
	)


class TestComputeDuplicateUpdates(unittest.TestCase):

	def test_status_carried_forward_onto_new_main(self):
		"""A prior ACKNOWLEDGED main carries onto a re-found main whose status is NEW."""
		prev = _vuln('prev', status='ACKNOWLEDGED')
		new = _vuln('new', status='NEW')
		updates = compute_duplicate_updates([prev], [new], copy_fields=['status'])
		assert updates['new']['status'] == 'ACKNOWLEDGED'

	def test_status_fixed_not_overwritten(self):
		"""A new main that is already FIXED keeps its value (FIXED is not 'unset')."""
		prev = _vuln('prev', status='ACKNOWLEDGED')
		new = _vuln('new', status='FIXED')
		updates = compute_duplicate_updates([prev], [new], copy_fields=['status'])
		assert 'status' not in updates['new']

	def test_prior_new_status_not_carried(self):
		"""A prior status of NEW is treated as unset and is not carried forward."""
		prev = _vuln('prev', status='NEW')
		new = _vuln('new', status='NEW')
		updates = compute_duplicate_updates([prev], [new], copy_fields=['status'])
		assert 'status' not in updates['new']

	def test_non_status_field_keeps_not_value_semantics(self):
		"""Generic fields still use the `not value` emptiness check."""
		# Prior verified=True copies onto new verified=False (falsy -> empty).
		prev = _vuln('prev', verified=True)
		new = _vuln('new', verified=False)
		updates = compute_duplicate_updates([prev], [new], copy_fields=['verified'])
		assert updates['new']['verified'] is True

		# Prior verified=False is empty -> nothing to copy.
		prev2 = _vuln('prev2', verified=False)
		new2 = _vuln('new2', verified=True)
		updates2 = compute_duplicate_updates([prev2], [new2], copy_fields=['verified'])
		assert 'verified' not in updates2['new2']


if __name__ == '__main__':
	unittest.main()
