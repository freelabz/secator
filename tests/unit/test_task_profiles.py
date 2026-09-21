"""Worker-profile regression checks.

A task's `profile` selects the Celery queue, and therefore the Kubernetes worker
pool and its resource request. Getting it wrong is not a tidiness issue: on GKE
Autopilot the small pool is admitted at 500m / 512 MiB, and a task that exceeds
that is either CPU-throttled or OOM-killed. The OOM kills PID 1, so the container
exits 137 with no output and the run surfaces as an abandoned task with NO error
message -- which is how `wpscan` failed 10/10 times for a month unnoticed.
"""
import unittest

from secator.tasks.arjun import arjun
from secator.tasks.bup import bup
from secator.tasks.dnsx import dnsx


class TestTaskProfiles(unittest.TestCase):
	def test_arjun_not_on_small(self):
		# ~284 MiB / ~566 mc observed in prod vs a 500m/512Mi admitted request.
		self.assertEqual(arjun.profile, 'medium')

	def test_bup_not_on_small(self):
		# ~365 MiB / ~551 mc observed in prod.
		self.assertEqual(bup.profile, 'medium')

	def test_dnsx_plain_stays_small(self):
		"""A plain resolve is tiny and must not be promoted (medium bills 2x memory)."""
		self.assertEqual(dnsx.profile({}), 'small')

	def test_dnsx_brute_is_promoted(self):
		"""`dnsx/brute` is wordlist-driven: ~449 MiB / ~503 mc over ~2h in prod."""
		self.assertEqual(dnsx.profile({'wordlist': 'combined_subdomains'}), 'medium')

	def test_dnsx_profile_does_not_raise_without_wordlist(self):
		"""Regression: resolving the wordlist opt with process=True raised on None."""
		try:
			dnsx.profile({})
		except Exception as e:  # pragma: no cover
			self.fail(f'dnsx.profile({{}}) raised {type(e).__name__}: {e}')


if __name__ == '__main__':
	unittest.main()
