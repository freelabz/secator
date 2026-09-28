"""trufflehog's source install must build the pinned release TAG, not upstream HEAD.

Regression: the `go build` install cloned the default branch while naming the checkout dir
after `install_version`, so it compiled whatever was on main that day. When upstream HEAD didn't
compile (e.g. a redeclaration error in pkg/engine) the source install failed even though the
pinned release built fine. Cloning `--branch [install_version]` makes the build reproducible.
"""
import unittest

from secator.tasks.trufflehog import trufflehog


class TestTrufflehogInstall(unittest.TestCase):

	def test_clone_pins_the_release_tag(self):
		# The clone must check out the pinned version tag, not the default branch (HEAD).
		self.assertIn('--branch [install_version]', trufflehog.install_cmd)

	def test_still_builds_from_source_into_bin(self):
		# Sanity: the source-build shape is preserved (build then move into the bin dir).
		self.assertIn('go build -o trufflehog', trufflehog.install_cmd)
		self.assertIn('git clone', trufflehog.install_cmd)


if __name__ == '__main__':
	unittest.main()
