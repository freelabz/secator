import unittest

from secator.hooks._dedup import build_baseline_index, compute_duplicate_updates
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


def _distinct_vuln(uuid):
	"""A vuln with a unique compare-key (name/id/matched_at)."""
	return Vulnerability(name=f'CVE-{uuid}', id=f'CVE-{uuid}', matched_at=f'host{uuid}:80', _uuid=uuid)


class TestBaselineIndexBounded(unittest.TestCase):
	"""#prod 2026-09-15: the baseline load OOM-killed a 2Gi worker. The baseline is now
	folded into a compact index whose peak size is O(distinct compare-keys), NOT O(docs),
	while dedup correctness against existing findings is preserved."""

	def test_index_is_bounded_by_distinct_keys_not_doc_count(self):
		# 10k baseline docs but only 1 distinct compare-key -> the index holds ONE entry.
		N = 10_000
		baseline = (_vuln(f'ws{i}') for i in range(N))  # all share name/id/matched_at
		index = build_baseline_index(baseline, copy_fields=['status'])
		assert len(index) == 1
		# The single entry still enumerates every baseline uuid (needed to tag them all).
		(entry,) = index.values()
		assert len(entry['uuids']) == N

	def test_genuine_duplicate_still_tagged_against_large_baseline(self):
		# Large baseline of unique findings + one that the new item duplicates.
		baseline = [_distinct_vuln(str(i)) for i in range(5_000)]
		baseline.append(_vuln('prev', status='ACKNOWLEDGED'))
		index = build_baseline_index(baseline, copy_fields=['status'])
		new = _vuln('new')  # same compare-key as 'prev'
		updates = compute_duplicate_updates([], [new], copy_fields=['status'], baseline_index=index)
		# New item becomes main, prior main flagged duplicate, and status carried forward.
		assert updates['new']['_context.workspace_duplicate'] is False
		assert updates['new']['status'] == 'ACKNOWLEDGED'
		assert 'prev' in updates['new']['_related']
		assert updates['prev']['_context.workspace_duplicate'] is True

	def test_prebuilt_index_matches_full_list_path(self):
		# The streaming/index path must be equivalent to passing the full baseline list.
		prev = _vuln('prev', status='ACKNOWLEDGED')
		new = _vuln('new')
		via_list = compute_duplicate_updates([prev], [new], copy_fields=['status'])
		index = build_baseline_index([prev], copy_fields=['status'])
		via_index = compute_duplicate_updates([], [new], copy_fields=['status'], baseline_index=index)
		assert via_list == via_index


if __name__ == '__main__':
	unittest.main()
