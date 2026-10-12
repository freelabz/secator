import unittest

from secator.estimation import (
	Estimate,
	estimate_scan,
	estimate_task,
	estimate_workflow,
	task_work_units,
	_demo,
)


class TestEstimation(unittest.TestCase):

	def test_demo_selfcheck(self):
		_demo()  # ships with the module; must not raise

	def test_human_buckets(self):
		self.assertEqual(Estimate(0.5, 0, 0, 'x').human(), '<1s')
		self.assertTrue(Estimate(30, 0, 0, 'x').human().endswith('s'))
		self.assertTrue(Estimate(600, 0, 0, 'x').human().endswith('min'))
		self.assertTrue(Estimate(7200, 0, 0, 'x').human().endswith('h'))
		self.assertTrue(Estimate(5 * 86400, 0, 0, 'x').human().endswith('d'))

	def test_port_parsing_drives_work(self):
		# all-ports >> top-100 >> explicit short list
		all_ports = task_work_units('nmap', {'ports': '-'})
		top100 = task_work_units('nmap', {'top_ports': 100})
		short = task_work_units('nmap', {'ports': '22,80,443'})
		rng = task_work_units('nmap', {'ports': '1-1024'})
		self.assertEqual(all_ports, 65535)
		self.assertEqual(top100, 100)
		self.assertEqual(short, 3)
		self.assertEqual(rng, 1024)

	def test_sv_multiplier(self):
		plain = task_work_units('nmap', {'top_ports': 1000})
		sv = task_work_units('nmap', {'top_ports': 1000, 'version_detection': True})
		self.assertGreater(sv, plain)

	def test_rate_is_the_footgun(self):
		# Same port surface, rate 1 must dwarf the default-rate estimate.
		slow = estimate_task('nmap', {'ports': '-', 'rate_limit': 1}, 1)
		fast = estimate_task('nmap', {'top_ports': 1000}, 1)
		self.assertGreater(slow.seconds, 3600)
		self.assertLess(fast.seconds, 1800)
		self.assertGreater(slow.seconds, fast.seconds * 100)

	def test_chunking_is_sublinear(self):
		one = estimate_task('nuclei', {}, 20)
		many = estimate_task('nuclei', {}, 2000)
		self.assertGreater(many.seconds, one.seconds)        # more work
		self.assertLess(many.seconds, one.seconds * 20)      # but parallelised

	def test_no_model_no_calibration_is_empty(self):
		e = estimate_task('some_unknown_tool', {}, 1)
		self.assertEqual(e.basis, 'empty')
		self.assertEqual(e.seconds, 0.0)

	def test_pure_observed_when_no_formula(self):
		# A fixed-battery task with calibration only.
		calib = {'subfinder': {'p50': 12.0, 'p90': 46.0, 'n': 55}}
		e = estimate_task('subfinder', {}, 2, calib)
		self.assertIn(e.basis, ('observed', 'blended'))
		self.assertGreater(e.high, e.seconds)

	def test_blend_weights_by_samples(self):
		calib = {'nmap': {'p50': 230.0, 'p90': 430.0, 'n': 300}}
		e = estimate_task('nmap', {'top_ports': 1000}, 1, calib)
		self.assertEqual(e.basis, 'blended')
		# observed (230) anchors the common case, algo (~9s) pulls down a little
		self.assertGreater(e.seconds, 100)
		self.assertLess(e.seconds, 230)

	def test_low_sample_calibration_ignored(self):
		calib = {'nmap': {'p50': 9999.0, 'p90': 9999.0, 'n': 1}}
		e = estimate_task('nmap', {'top_ports': 1000}, 1, calib)
		self.assertEqual(e.basis, 'algorithmic')  # n<3 dropped

	def test_workflow_group_is_max_not_sum(self):
		parallel = {'tasks': {'_group/g': {'nmap': {}, 'naabu': {}}}}
		sequential = {'tasks': {'nmap': {}, 'naabu': {}}}
		p = estimate_workflow(parallel, {}, 1)
		s = estimate_workflow(sequential, {}, 1)
		self.assertLess(p.seconds, s.seconds)

	def test_workflow_skips_plumbing_keys(self):
		wf = {'tasks': {'httpx': {'targets_': [{'field': 'url'}]}}}
		e = estimate_workflow(wf, {}, 1)
		self.assertGreater(e.seconds, 0)

	def test_scan_sums_workflows_from_registry(self):
		registry = {
			'wf_a': {'type': 'workflow', 'tasks': {'nmap': {}}},
			'wf_b': {'type': 'workflow', 'tasks': {'httpx': {}}},
		}
		scan = {'type': 'scan', 'workflows': {'wf_a': {}, 'wf_b': {}}}
		full = estimate_scan(scan, {}, 1, registry=registry)
		only_a = estimate_scan({'type': 'scan', 'workflows': {'wf_a': {}}}, {}, 1, registry=registry)
		self.assertAlmostEqual(
			full.seconds,
			only_a.seconds + estimate_workflow(registry['wf_b'], {}, 1).seconds,
			places=3,
		)

	def test_scan_skips_unknown_workflows(self):
		scan = {'type': 'scan', 'workflows': {'missing': {}}}
		e = estimate_scan(scan, {}, 1, registry={})
		self.assertEqual(e.basis, 'empty')

	def test_to_dict_shape(self):
		d = estimate_task('nmap', {'top_ports': 1000}, 1).to_dict()
		self.assertEqual(
			set(d),
			{'seconds', 'low', 'high', 'basis', 'human', 'human_high'},
		)


if __name__ == '__main__':
	unittest.main()
