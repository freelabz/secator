"""Scope is enforced on task OUTPUT, not just input (secator/runners/_base.py:add_result).

Passive tasks (gau, subfinder, xurlfind3r, ...) persist their whole archive, so before this guard a
scoped run still minted out-of-scope discovered hosts into Subdomain/Url/Target findings (a prod
workspace accumulated ~65k out-of-scope target findings this way). The guard drops host-bearing
findings whose host is out of scope at the single output choke point, reusing the input filter's
predicate (secator.scope.host_in_scope). It is OPT-IN per task via `output_scope_filter` (default
False, so un-opted tasks pay zero per-finding cost) and a no-op when no scope is set.
"""
import unittest

from secator.decorators import task
from secator.runners import PythonRunner
from secator.output_types import Subdomain, Url, Target, Vulnerability


IN = 'app.example.com'          # in-scope input
IN_SUB = 'api.example.com'      # in-scope discovered host
OUT_HOST = 'assets.example.net'     # out-of-scope discovered host (classifies as a network host)
# Out-of-scope host with an underscore label (cloud PTR-style). Since #1393 autodetect_type
# classifies these as hosts (rfc_2782), so the guard drops them too instead of failing open.
UNDERSCORE_OUT = 'bucket_1234.example.net'


@task()
class scopeprobe(PythonRunner):
	input_types = None
	output_types = [Subdomain, Url, Target, Vulnerability]
	output_scope_filter = True   # opt in

	def yielder(self):
		yield Subdomain(host=IN_SUB, domain='example.com')
		yield Subdomain(host=OUT_HOST, domain='example.net')
		yield Subdomain(host=UNDERSCORE_OUT, domain='example.net')
		yield Url(url=f'https://{IN_SUB}/a')
		yield Url(url=f'https://{OUT_HOST}/a')
		yield Target(name=OUT_HOST)
		yield Vulnerability(name='V', severity='high', confidence='high', matched_at=IN_SUB)


@task()
class scopeprobe_noopt(PythonRunner):
	"""Same output, but does NOT opt in (output_scope_filter stays False)."""
	input_types = None
	output_types = [Subdomain, Url, Target, Vulnerability]

	def yielder(self):
		yield Subdomain(host=IN_SUB, domain='example.com')
		yield Subdomain(host=OUT_HOST, domain='example.net')
		yield Target(name=OUT_HOST)


def _vals(results, _type, attr):
	return {getattr(r, attr) for r in results if r._type == _type}


class TestScopeOutputGuard(unittest.TestCase):

	def _run(self, **opts):
		return scopeprobe(inputs=[IN], **opts).run()

	def test_scope_drops_out_of_scope_output(self):
		results = self._run(in_scope=['*.example.com'])

		subs = _vals(results, 'subdomain', 'host')
		self.assertIn(IN_SUB, subs)
		self.assertNotIn(OUT_HOST, subs)

		url_hosts = _vals(results, 'url', 'host')
		self.assertIn(IN_SUB, url_hosts)
		self.assertNotIn(OUT_HOST, url_hosts)

		targets = _vals(results, 'target', 'name')
		self.assertIn(IN, targets)          # in-scope input Target minted
		self.assertNotIn(OUT_HOST, targets)  # out-of-scope discovered Target dropped

		# Hostless findings (vulns/tags/info) are never scoped.
		self.assertTrue(any(r._type == 'vulnerability' for r in results))

		# Underscore hosts are network hosts since #1393 -> scoped like any other host.
		self.assertNotIn(UNDERSCORE_OUT, subs)

	def test_default_run_persists_everything(self):
		results = self._run()  # no scope -> guard is a no-op

		subs = _vals(results, 'subdomain', 'host')
		self.assertIn(IN_SUB, subs)
		self.assertIn(OUT_HOST, subs)

		self.assertIn(OUT_HOST, _vals(results, 'target', 'name'))

	def test_opt_out_task_does_not_filter_even_with_scope(self):
		# A task without output_scope_filter keeps out-of-scope findings even with a
		# scope set — the guard is opt-in (zero cost for tasks that don't need it).
		results = scopeprobe_noopt(inputs=[IN], in_scope=['*.example.com']).run()
		self.assertIn(OUT_HOST, _vals(results, 'subdomain', 'host'))
		self.assertIn(OUT_HOST, _vals(results, 'target', 'name'))


if __name__ == '__main__':
	unittest.main()
