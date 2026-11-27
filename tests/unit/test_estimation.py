import unittest
from unittest import mock

from secator.estimation import TASK_MODELS, Estimate, estimate, estimate_task, target_seconds
from secator.loader import discover_tasks
from secator.template import TemplateLoader


def _load(name):
	return TemplateLoader(name=name)


class TestEstimation(unittest.TestCase):

	def test_human_buckets(self):
		self.assertEqual(Estimate(0.5, 0, 0, 'x').human(), '<1s')
		self.assertTrue(Estimate(30, 0, 0, 'x').human().endswith('s'))
		self.assertTrue(Estimate(600, 0, 0, 'x').human().endswith('min'))
		self.assertTrue(Estimate(7200, 0, 0, 'x').human().endswith('h'))
		self.assertTrue(Estimate(5 * 86400, 0, 0, 'x').human().endswith('d'))

	def test_every_task_has_a_model(self):
		for cls in discover_tasks():
			with self.subTest(task=cls.__name__):
				self.assertIn(cls.__name__, TASK_MODELS)
				self.assertNotEqual(estimate_task(cls.__name__, {}, 1).basis, 'empty')

	def test_port_parsing_drives_work(self):
		base = target_seconds('naabu', {'ports': '22'})
		self.assertAlmostEqual(target_seconds('naabu', {'ports': '22,80,443'}), 3 * base)
		self.assertAlmostEqual(target_seconds('naabu', {'ports': '1-1024'}), 1024 * base)
		self.assertAlmostEqual(target_seconds('naabu', {'top_ports': 100}), 100 * base)
		self.assertAlmostEqual(target_seconds('naabu', {'ports': '-'}), 65535 * base)

	def test_all_ports_nmap_is_minutes(self):
		default = estimate_task('nmap', {}, 1).seconds
		all_ports = estimate_task('nmap', {'ports': '-'}, 1).seconds
		self.assertLess(default, 60)
		self.assertGreater(all_ports, 10 * 60)
		self.assertLess(all_ports, 60 * 60)

	def test_masscan_is_rate_driven_without_version_detection(self):
		masscan = target_seconds('masscan', {'ports': '-'})
		self.assertAlmostEqual(masscan, 65535 / 100)  # masscan default rate: 100 pkt/s
		self.assertEqual(target_seconds('masscan', {'ports': '-', 'version_detection': True}), masscan)
		self.assertGreater(target_seconds('nmap', {'ports': '-', 'version_detection': True}),
						target_seconds('nmap', {'ports': '-'}))
		self.assertAlmostEqual(target_seconds('masscan', {'ports': '-', 'rate_limit': 10000}), 65535 / 10000)

	def test_rate_is_the_footgun(self):
		slow = estimate_task('nmap', {'ports': '-', 'rate_limit': 1}, 1)
		self.assertGreater(slow.seconds, 12 * 3600)

	def test_rate_limit_caps_or_sets_the_rate(self):
		nmap = target_seconds('nmap', {'ports': '-'})
		self.assertEqual(target_seconds('nmap', {'ports': '-', 'rate_limit': 100000}), nmap)  # --max-rate: a cap
		self.assertLess(target_seconds('naabu', {'ports': '-', 'rate_limit': 10000}),
						target_seconds('naabu', {'ports': '-'}))  # -rate: the send rate
		self.assertGreater(target_seconds('nmap', {'ports': '-', 'delay': 1}), 65535)  # --scan-delay
		ffuf = target_seconds('ffuf', {})
		self.assertEqual(target_seconds('ffuf', {'rate_limit': 100000}), ffuf)
		self.assertGreater(target_seconds('ffuf', {'rate_limit': 10}), ffuf)

	def test_crawl_depth_is_capped(self):
		self.assertGreater(target_seconds('katana', {'depth': 3}), target_seconds('katana', {'depth': 1}))
		self.assertEqual(target_seconds('katana', {'depth': 10}), target_seconds('katana', {'depth': 5}))

	def test_chained_and_ping_scans_ignore_ports(self):
		self.assertLess(target_seconds('nmap', {'ports': '-', 'ping_scan': True}), 1)
		self.assertLess(target_seconds('nmap', {'ports': '-', 'ports_': [{'type': 'port'}]}), 1)

	def test_dnsx_brute_force_only_with_a_wordlist(self):
		self.assertLess(target_seconds('dnsx', {}), 1)
		self.assertGreater(target_seconds('dnsx', {'wordlist': 'combined_subdomains'}), 60)

	def test_chunking_is_sublinear(self):
		one = estimate_task('nuclei', {}, 20)
		many = estimate_task('nuclei', {}, 2000)
		self.assertGreater(many.seconds, one.seconds)
		self.assertLess(many.seconds, one.seconds * 20)

	def test_unknown_task_without_calibration_is_empty(self):
		e = estimate_task('some_unknown_tool', {}, 1)
		self.assertEqual((e.basis, e.seconds), ('empty', 0.0))

	def test_observed_only_for_unknown_task(self):
		e = estimate_task('some_unknown_tool', {}, 2, {'some_unknown_tool': {'p50': 12.0, 'p90': 46.0, 'n': 55}})
		self.assertEqual(e.basis, 'observed')
		self.assertGreater(e.high, e.seconds)

	def test_blend_weights_by_samples(self):
		e = estimate_task('nmap', {}, 1, {'nmap': {'p50': 230.0, 'p90': 430.0, 'n': 300}})
		self.assertEqual(e.basis, 'blended')
		self.assertAlmostEqual(e.seconds, 0.7 * 230 + 0.3 * estimate_task('nmap', {}, 1).seconds)  # trust capped at 70%

	def test_low_sample_calibration_ignored(self):
		e = estimate_task('nmap', {}, 1, {'nmap': {'p50': 9999.0, 'p90': 9999.0, 'n': 1}})
		self.assertEqual(e.basis, 'algorithmic')

	def test_group_is_max_not_sum(self):
		group = {'name': 'g', 'type': 'workflow', 'tasks': {'_group/g': {'nmap': {}, 'naabu': {}}}}
		chain = {'name': 'c', 'type': 'workflow', 'tasks': {'nmap': {}, 'naabu': {}}}
		self.assertLess(estimate(group).seconds, estimate(chain).seconds)

	def test_if_conditions_honoured(self):
		host_recon = _load('workflow/host_recon')

		def tasks_run(opts):
			with mock.patch('secator.estimation.estimate_task', wraps=estimate_task) as spy:
				seconds = estimate(host_recon, opts).seconds
			return seconds, [c.args[0] for c in spy.call_args_list]

		default, default_tasks = tasks_run({})
		with_nuclei, nuclei_tasks = tasks_run({'nuclei': True})
		self.assertNotIn('naabu', default_tasks)
		self.assertNotIn('nuclei/url', default_tasks)
		self.assertIn('nuclei/url', nuclei_tasks)
		self.assertGreater(with_nuclei, default)
		self.assertEqual(tasks_run({'passive': True})[1], ['search_vulns'])  # the only offline step

	def test_all_ports_propagates_to_workflows_and_scans(self):
		nmap_extra = estimate_task('nmap', {'ports': '-'}, 1).seconds - estimate_task('nmap', {}, 1).seconds
		for name in ('workflow/host_recon', 'scan/host', 'scan/network'):
			with self.subTest(name=name):
				config = _load(name)
				extra = estimate(config, {'ports': '-'}).seconds - estimate(config).seconds
				self.assertAlmostEqual(extra, nmap_extra, delta=1)

	def test_task_config(self):
		self.assertEqual(estimate({'name': 'nmap', 'type': 'task'}).seconds, estimate_task('nmap', {}, 1).seconds)

	def test_to_dict_shape(self):
		d = estimate_task('nmap', {}, 1).to_dict()
		self.assertEqual(set(d), {'seconds', 'low', 'high', 'basis', 'human', 'human_high'})


if __name__ == '__main__':
	unittest.main()
