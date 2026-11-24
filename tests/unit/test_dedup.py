import unittest
from dataclasses import fields

from secator.config import CONFIG
from secator.hooks._dedup import baseline_fields, build_baseline_index, compute_duplicate_updates
from secator.output_types import OUTPUT_TYPES, Domain, Port, Progress, Stat, Subdomain, Technology, Url, Vulnerability


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

	def test_poc_carried_forward_onto_new_main(self):
		"""A recorded PoC on a demoted main carries onto the re-found main.

		Regression: add_vuln_poc fills `poc` on the finding that is main at the
		time; a later rescan creates a new main and demotes the poc'd doc to a
		hidden duplicate. Without `poc` in copy_fields the exploitation report is
		orphaned on the duplicate and the workspace finding shows an empty PoC.
		"""
		prev = _vuln('prev', poc='## Exploitation Report\ncurl ... -> alert(1)')
		new = _vuln('new')  # re-found, no poc yet
		updates = compute_duplicate_updates([prev], [new], copy_fields=['poc'])
		assert updates['new']['poc'] == '## Exploitation Report\ncurl ... -> alert(1)'

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


class TestBaselineFields(unittest.TestCase):
	"""Backends fetch only baseline_fields() for the dedup baseline, so a projected doc must
	group and carry fields forward exactly like the full doc."""

	COPY_FIELDS = CONFIG.addons.mongodb.duplicate_main_copy_fields

	def _samples(self):
		return [
			Vulnerability(
				name='CVE-2025-53020', id='CVE-2025-53020', matched_at='host:80', severity='high',
				description='long text ' * 50, extra_data={'raw': 'x' * 500}, status='FIXED', poc='curl x',
				tags=['t1'], _related=['r1'],
			),
			Url(
				url='http://host/a', status_code=200, title='t', response_headers={'server': 'nginx'},
				screenshot_path='/s.png', verified=True,
			),
			Port(port=443, ip='1.2.3.4', state='open', service_name='https', extra_data={'banner': 'b'}),
			Subdomain(host='a.host', domain='host', sources=['crt']),
			Technology(product='nginx', match='host:80', version='1.2', extra_data={'x': 1}),
			Progress(percent=40, extra_data={'rate': '1kpps'}, _source='masscan'),
		]

	def test_derived_fields_survive_projection(self):
		"""__post_init__ derives some kept fields from others (Url.verified from confidence +
		status_code, Domain.alive from status): their inputs must be projected too, including
		when extra copy fields are configured."""
		copy_fields = [*self.COPY_FIELDS, 'status_code']
		names = baseline_fields(copy_fields)
		samples = [
			Url(url='http://host/low', confidence='low', status_code=200, verified=False),
			Domain(domain='host.com', status=['clientTransferProhibited active']),
		]
		for i, item in enumerate(samples):
			with self.subTest(type=item.get_name()):
				item._uuid = f'd{i}'
				doc = item.toDict()
				full = type(item).load(doc)
				projected = type(item).load({k: v for k, v in doc.items() if k in names})
				full._uuid = projected._uuid = item._uuid
				self.assertEqual(projected._compare_key(), full._compare_key())
				self.assertEqual(
					build_baseline_index([projected], copy_fields),
					build_baseline_index([full], copy_fields),
				)
		self.assertFalse(Url.load({k: v for k, v in samples[0].toDict().items() if k in names}).verified)

	def test_no_type_compares_on_extra_data(self):
		for otype in OUTPUT_TYPES:
			for f in fields(otype):
				if f.name == 'extra_data':
					self.assertFalse(f.compare, otype.get_name())

	def test_equality_ignores_extra_data(self):
		# Same progress point / same process snapshot, whatever the free-form extras.
		a = Progress(percent=40, extra_data={'rate': '1kpps'}, _source='masscan')
		b = Progress(percent=40, extra_data={'rate': '2kpps'}, _source='masscan')
		self.assertEqual(a, b)
		self.assertNotEqual(a, Progress(percent=41, _source='masscan'))
		self.assertNotEqual(a, Progress(percent=40, _source='nmap'))
		s1 = Stat(name='nmap', pid=1, cpu=5, memory=10, memory_limit=-1, extra_data={'x': 1})
		s2 = Stat(name='nmap', pid=1, cpu=5, memory=10, memory_limit=-1, extra_data={'x': 2})
		self.assertEqual(s1, s2)
		self.assertNotEqual(s1, Stat(name='nmap', pid=2, cpu=5, memory=10, memory_limit=-1))

	def test_covers_every_equality_field(self):
		names = set(baseline_fields(self.COPY_FIELDS))
		for otype in OUTPUT_TYPES:
			for f in fields(otype):
				if f.compare:
					self.assertIn(f.name, names, f'{otype.get_name()}.{f.name}')
		self.assertTrue({'_type', '_related', *self.COPY_FIELDS} <= names)

	def test_drops_heavy_fields(self):
		names = set(baseline_fields(self.COPY_FIELDS))
		for heavy in ('extra_data', 'description', 'response_headers', 'request_headers', '_context'):
			self.assertNotIn(heavy, names)

	def test_projected_doc_indexes_like_full_doc(self):
		names = baseline_fields(self.COPY_FIELDS)
		for i, item in enumerate(self._samples()):
			with self.subTest(type=item.get_name()):
				item._uuid = f'u{i}'
				doc = item.toDict()
				projected = type(item).load({k: v for k, v in doc.items() if k in names})
				projected._uuid = item._uuid
				self.assertEqual(projected._compare_key(), item._compare_key())
				self.assertEqual(
					build_baseline_index([projected], self.COPY_FIELDS),
					build_baseline_index([item], self.COPY_FIELDS),
				)


if __name__ == '__main__':
	unittest.main()


def _reference_duplicate_updates(workspace_findings, untagged_findings, copy_fields=None):
	"""The original pairwise (O(n²)) implementation, kept as an oracle for the grouped one."""
	copy_fields = copy_fields or []
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
			db_updates[uuid_] = {'_context.workspace_duplicate': True, '_tagged': True}
	return db_updates


class TestComputeDuplicateUpdatesGroupedEquivalence(unittest.TestCase):
	"""The grouped implementation must produce byte-identical updates (values AND key order)
	to the original pairwise one, on mixed types, baseline hits, copy fields and repeated uuids."""

	def _random_findings(self, rng, n, prefix):
		out = []
		for i in range(n):
			kind = rng.randrange(4)
			k = rng.randrange(max(1, n // 4))
			if kind == 0:
				f = Url(url=f'http://h{k}.test/', status_code=rng.choice([200, 404]))
			elif kind == 1:
				f = Port(port=80 + k % 3, ip=f'10.0.0.{k % 5}', host='h')
			elif kind == 2:
				f = Subdomain(host=f's{k}.example.test', domain='example.test')
			else:
				f = _vuln(None, status=rng.choice(['', 'ACKNOWLEDGED']))
				f.matched_at = f'host:{k % 3}'
			# Occasionally reuse a uuid to exercise the repeated-uuid path.
			f._uuid = f'{prefix}{rng.randrange(n) if rng.random() < 0.05 else i}'
			out.append(f)
		return out

	def test_grouped_matches_pairwise_reference(self):
		import json
		import random
		for seed in range(25):
			rng = random.Random(seed)
			baseline = self._random_findings(rng, rng.randrange(0, 40), 'b')
			untagged = self._random_findings(rng, rng.randrange(1, 120), 'u')
			copy_fields = rng.choice([[], ['status'], ['status', 'verified']])
			expected = _reference_duplicate_updates(baseline, untagged, copy_fields)
			actual = compute_duplicate_updates(baseline, untagged, copy_fields=copy_fields)
			self.assertEqual(
				json.dumps(actual, default=str), json.dumps(expected, default=str), f'seed={seed}')

	def test_accepts_any_iterable(self):
		items = [Url(url='http://a.test/', _uuid='1'), Url(url='http://a.test/', _uuid='2')]
		self.assertEqual(
			compute_duplicate_updates([], iter(items)), _reference_duplicate_updates([], items))
