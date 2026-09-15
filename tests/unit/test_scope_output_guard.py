"""Scope is enforced on task OUTPUT, not just input (secator/runners/_base.py:add_result).

Passive tasks (gau, subfinder, xurlfind3r, ...) persist their whole archive, so before this guard a
scoped run still minted out-of-scope discovered hosts into Subdomain/Url/Target findings (a prod
workspace accumulated ~65k out-of-scope target findings this way). The guard drops host-bearing
findings whose host is out of scope at the single output choke point, reusing the input filter's
predicate (secator.scope.host_in_scope), and is a no-op when no scope is set.
"""
import unittest

from secator.decorators import task
from secator.runners import PythonRunner
from secator.output_types import Subdomain, Url, Target, Vulnerability


IN = 'app.vps592398.ovh.net'          # in-scope input
IN_SUB = 'api.vps592398.ovh.net'      # in-scope discovered host
OUT_HOST = 's3.bhs.cloud.ovh.net'     # out-of-scope discovered host (classifies as a network host)
# Real-world out-of-scope host from the incident: the underscore makes it classify as `str`
# (non-network), so host_in_scope fail-opens it — exactly as the INPUT filter already does. This
# `str`-host blind spot is a pre-existing limitation of the shared predicate, not of this guard.
STR_OUT = 'xnkib_227077.s3.bhs.cloud.ovh.net'


@task()
class scopeprobe(PythonRunner):
	input_types = None
	output_types = [Subdomain, Url, Target, Vulnerability]

	def yielder(self):
		yield Subdomain(host=IN_SUB, domain='vps592398.ovh.net')
		yield Subdomain(host=OUT_HOST, domain='cloud.ovh.net')
		yield Subdomain(host=STR_OUT, domain='cloud.ovh.net')
		yield Url(url=f'https://{IN_SUB}/a')
		yield Url(url=f'https://{OUT_HOST}/a')
		yield Target(name=OUT_HOST)
		yield Vulnerability(name='V', severity='high', confidence='high', matched_at=IN_SUB)


def _vals(results, _type, attr):
	return {getattr(r, attr) for r in results if r._type == _type}


class TestScopeOutputGuard(unittest.TestCase):

	def _run(self, **opts):
		return scopeprobe(inputs=[IN], **opts).run()

	def test_scope_drops_out_of_scope_output(self):
		results = self._run(in_scope=['*.vps592398.ovh.net'])

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

		# Documented pass-through: a `str`-classified host fail-opens (same as the input filter).
		self.assertIn(STR_OUT, subs)

	def test_default_run_persists_everything(self):
		results = self._run()  # no scope -> guard is a no-op

		subs = _vals(results, 'subdomain', 'host')
		self.assertIn(IN_SUB, subs)
		self.assertIn(OUT_HOST, subs)

		self.assertIn(OUT_HOST, _vals(results, 'target', 'name'))


if __name__ == '__main__':
	unittest.main()
