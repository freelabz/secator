import unittest

from secator.hooks._dedup import compute_duplicate_updates
from secator.output_types import Vulnerability


def _vuln(uuid, status='', verified=False, **kwargs):
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
		"""A prior ACKNOWLEDGED main carries onto a re-found main with no status yet."""
		prev = _vuln('prev', status='ACKNOWLEDGED')
		new = _vuln('new')  # untouched -> status '' (empty, like any other field)
		updates = compute_duplicate_updates([prev], [new], copy_fields=['status'])
		assert updates['new']['status'] == 'ACKNOWLEDGED'

	def test_status_fixed_not_overwritten(self):
		"""A new main that already has a status keeps its value (not empty)."""
		prev = _vuln('prev', status='ACKNOWLEDGED')
		new = _vuln('new', status='FIXED')
		updates = compute_duplicate_updates([prev], [new], copy_fields=['status'])
		assert 'status' not in updates['new']

	def test_prior_empty_status_not_carried(self):
		"""A prior empty status has nothing to carry forward."""
		prev = _vuln('prev')  # status '' (empty)
		new = _vuln('new')
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
