"""ffuf host-header (virtual host) fuzzing against catch-all servers.

A catch-all / wildcard virtual host answers every name, sometimes with one of several
pages, which ffuf's own auto-calibration does not capture. The task fingerprints the
answer to random, non-existent names and drops hits that answer the same way.
"""
import sys
import threading
import unittest
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

from secator.output_types import Subdomain, Url
from secator.tasks import ffuf as ffuf_task
from secator.tasks.ffuf import (
	dominant_fingerprint_warning, matches_vhost_baseline, probe_vhost_baseline, random_dns_label,
	response_fingerprints)

ffuf_module = sys.modules['secator.tasks.ffuf']

PAGE_A = b'<html><title>Shop</title><body>Home page, variant A</body></html>'
PAGE_B = b'<html>\n<head><title>Shop</title></head>\n<body>Home page, variant B</body>\n</html>\n'
REAL = b'<html>real site</html>'


class _CatchAll(BaseHTTPRequestHandler):
	"""Answers any Host with page A or B (alternating), except www.<base>."""
	count = 0

	def log_message(self, *args):
		pass

	def do_GET(self):
		host = self.headers.get('Host', '')
		if host.startswith('www.'):
			body = REAL
		else:
			_CatchAll.count += 1
			body = PAGE_A if _CatchAll.count % 2 else PAGE_B
		self.send_response(200)
		self.send_header('Content-Length', str(len(body)))
		self.end_headers()
		self.wfile.write(body)


def _opts(**values):
	defaults = {'subs': True, 'follow_redirect': False, 'auto_calibration': True, 'method': None,
		'proxy': None, 'timeout': 5}
	defaults.update(values)
	return lambda name: defaults.get(name)


def _fake_task(baseline=(), **opts):
	return SimpleNamespace(
		headers={'Host': 'FUZZ.example.test', 'User-Agent': 'x'},
		get_opt_value=_opts(**opts),
		vhost_baseline=set(baseline),
		vhost_fingerprints=Counter(),
		vhost_dropped=0,
		has_fuzz_keyword=False,
	)


def _hit(host, status=200, length=10, words=2, lines=1, redirect=''):
	return {
		'host': host, 'url': 'http://example.test', 'status': status, 'length': length, 'words': words,
		'lines': lines, 'content-type': 'text/html', 'redirectlocation': redirect, 'duration': 1000,
	}


class TestFingerprints(unittest.TestCase):

	def test_counts_like_ffuf(self):
		self.assertEqual(
			response_fingerprints(200, PAGE_B),
			{('size', 200, len(PAGE_B)), ('shape', 200, len(PAGE_B.split(b' ')), 5)})

	def test_matches_size_or_shape(self):
		baseline = response_fingerprints(200, PAGE_A)
		self.assertTrue(matches_vhost_baseline(baseline, 200, len(PAGE_A), 0, 0))
		# Same shape, other size (a page echoing the requested name).
		words = len(PAGE_A.split(b' '))
		self.assertTrue(matches_vhost_baseline(baseline, 200, len(PAGE_A) + 7, words, 1))
		self.assertFalse(matches_vhost_baseline(baseline, 404, len(PAGE_A), words, 1))
		self.assertFalse(matches_vhost_baseline(baseline, 200, 3, 9, 9))

	def test_random_label_is_a_valid_dns_label(self):
		for _ in range(50):
			label = random_dns_label()
			self.assertRegex(label, r'^[a-z][a-z0-9]{11}$')


class TestBaselineProbe(unittest.TestCase):

	def setUp(self):
		self.server = ThreadingHTTPServer(('127.0.0.1', 0), _CatchAll)
		threading.Thread(target=self.server.serve_forever, daemon=True).start()
		self.url = f'http://127.0.0.1:{self.server.server_address[1]}'
		self.running = True

	def tearDown(self):
		self._stop()

	def _stop(self):
		if self.running:
			self.server.shutdown()
			self.server.server_close()
			self.running = False

	def test_probe_captures_every_catch_all_page(self):
		baseline = probe_vhost_baseline(_fake_task(), self.url, 'example.test')
		self.assertIn(('size', 200, len(PAGE_A)), baseline)
		self.assertIn(('size', 200, len(PAGE_B)), baseline)
		self.assertNotIn(('size', 200, len(REAL)), baseline)

	def test_unreachable_target_gives_an_empty_baseline(self):
		self._stop()
		self.assertEqual(probe_vhost_baseline(_fake_task(timeout=1), self.url, 'example.test', probes=2), set())


class TestOnJsonLoaded(unittest.TestCase):

	def _run(self, task, item):
		return list(ffuf_task.on_json_loaded(task, item))

	def test_drops_hits_answering_like_a_random_name(self):
		task = _fake_task(baseline=response_fingerprints(200, PAGE_A))
		self.assertEqual(self._run(task, _hit('x.example.test', length=len(PAGE_A), words=5)), [])
		self.assertEqual(task.vhost_dropped, 1)

	def test_host_header_hit_is_not_a_verified_url(self):
		task = _fake_task()
		url, sub = self._run(task, _hit('api.example.test'))
		self.assertIsInstance(url, Url)
		self.assertFalse(url.verified)
		self.assertEqual(url.request_headers['Host'], 'api.example.test')
		self.assertIsInstance(sub, Subdomain)
		self.assertFalse(sub.verified)
		self.assertEqual(sum(task.vhost_fingerprints.values()), 1)

	def test_path_fuzzing_url_stays_verified(self):
		task = _fake_task(subs=False)
		task.headers = {'User-Agent': 'x'}
		(url,) = self._run(task, _hit('example.test'))
		self.assertTrue(url.verified)

	def test_is_redirect_needs_a_location_or_a_3xx(self):
		task = _fake_task(follow_redirect=True)
		url, sub = self._run(task, _hit('a.example.test'))
		self.assertFalse(url.is_redirect)
		self.assertFalse(sub.extra_data['http_redirect'])
		url, _ = self._run(task, _hit('b.example.test', redirect='https://b.example.test/'))
		self.assertTrue(url.is_redirect)
		url, _ = self._run(_fake_task(), _hit('c.example.test', status=301))
		self.assertTrue(url.is_redirect)


class TestOnStart(unittest.TestCase):

	def _task(self, cmd):
		return SimpleNamespace(
			cmd=cmd, inputs=['http://example.test'], vhost_base='example.test', _print=lambda *a, **k: None)

	def test_baseline_replaces_auto_calibration(self):
		task = self._task('ffuf -noninteractive -u http://example.test -json -ac -H Host:FUZZ.example.test -acx')
		original = ffuf_module.probe_vhost_baseline
		ffuf_module.probe_vhost_baseline = lambda *a, **k: {('size', 200, 10)}
		try:
			ffuf_task.on_start(task)
		finally:
			ffuf_module.probe_vhost_baseline = original
		self.assertEqual(task.vhost_baseline, {('size', 200, 10)})
		self.assertNotIn(' -ac ', task.cmd + ' ')
		self.assertIn('-acx', task.cmd)

	def test_empty_baseline_keeps_auto_calibration(self):
		task = self._task('ffuf -u http://example.test -ac')
		original = ffuf_module.probe_vhost_baseline
		ffuf_module.probe_vhost_baseline = lambda *a, **k: set()
		try:
			ffuf_task.on_start(task)
		finally:
			ffuf_module.probe_vhost_baseline = original
		self.assertTrue(task.cmd.endswith(' -ac'))


class TestOutputHandling(unittest.TestCase):

	def test_splits_result_glued_to_progress(self):
		line = ':: Progress: [5/200] :: Job [1/1] :: 9 req/sec :: Duration: [0:00:01] :: Errors: 0 ::{"input":{"FUZZ":"YQ=="}}'  # noqa: E501
		parts = list(ffuf_task.on_line(SimpleNamespace(), line))
		self.assertEqual(parts[1], '{"input":{"FUZZ":"YQ=="}}')
		self.assertTrue(parts[0].startswith(':: Progress'))

	def test_dominant_fingerprint_warning(self):
		self.assertIsNone(dominant_fingerprint_warning(Counter({(200, 10, 2, 1): 9})))
		self.assertIsNone(dominant_fingerprint_warning(Counter({(200, 10, 2, 1): 7, (200, 99, 9, 3): 5})))
		warning = dominant_fingerprint_warning(Counter({(403, 553, 20, 1): 90, (200, 99, 9, 3): 5}))
		self.assertIn('90 of 95', warning)
		self.assertIn('catch-all', warning)


if __name__ == '__main__':
	unittest.main()
