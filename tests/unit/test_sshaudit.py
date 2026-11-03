import unittest

from secator.output_types import Vulnerability
from secator.tasks.sshaudit import sshaudit


class TestSshauditOnJsonLoaded(unittest.TestCase):
	"""on_json_loaded must tolerate ssh-audit emitting algorithm entries as bare
	strings (e.g. an unrecognized host key 'ssh-rsa1') instead of {algorithm, notes} dicts."""

	def _run(self, item):
		return list(sshaudit.on_json_loaded(None, item))

	def test_bare_string_host_key_does_not_crash(self):
		# The exact payload that raised: AttributeError: 'str' object has no attribute 'get'
		item = {
			'target': 'scanme.nmap.org:22', 'banner': {'raw': ''}, 'cves': [],
			'enc': [], 'mac': [], 'kex': [], 'key': ['ssh-rsa1'],
			'fingerprints': [{'fp': None, 'type': 'ssh-rsa1'}], 'recommendations': {},
		}
		self.assertIsInstance(self._run(item), list)  # must not raise

	def test_dict_entry_with_failure_still_yields_vulnerability(self):
		item = {
			'target': 'h:22', 'banner': {'raw': ''}, 'cves': [],
			'enc': [], 'mac': [], 'kex': [],
			'key': [{'algorithm': 'ssh-rsa', 'notes': {'fail': ['weak']}}],
		}
		vulns = [r for r in self._run(item) if isinstance(r, Vulnerability)]
		self.assertTrue(any(v.extra_data.get('algorithm') == 'ssh-rsa' for v in vulns))

	def test_mixed_string_and_dict_entries_do_not_crash(self):
		item = {
			'target': 'h:22', 'banner': {'raw': ''}, 'cves': [],
			'enc': ['aes128-cbc', {'algorithm': 'aes256-cbc', 'notes': {'fail': ['x']}}],
			'mac': [], 'kex': [], 'key': [],
		}
		self.assertIsInstance(self._run(item), list)


if __name__ == '__main__':
	unittest.main()
