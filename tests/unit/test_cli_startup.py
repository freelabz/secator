"""CLI startup must not pay for heavy optional imports that only a few commands need."""
import subprocess
import sys
import unittest

LAZY_MODULES = ('fp.fp', 'dns.resolver', 'jinja2')


class TestCliStartupImports(unittest.TestCase):

	def test_heavy_modules_not_imported_by_cli(self):
		code = (
			'import sys, secator.cli; '
			f'print(",".join(m for m in {LAZY_MODULES!r} if m in sys.modules))'
		)
		out = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, check=True)
		self.assertEqual(out.stdout.strip().splitlines()[-1] if out.stdout.strip() else '', '')
