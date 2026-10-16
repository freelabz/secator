import tempfile
import unittest
from pathlib import Path
from string import Template

from secator.definitions import ADDONS_ENABLED


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestDynamicAiModes(unittest.TestCase):
	def setUp(self):
		self.tmp = Path(tempfile.mkdtemp())

	def _write(self, name, content):
		(self.tmp / f'{name}.txt').write_text(content)

	def test_full_frontmatter_mode(self):
		from secator.ai.prompts import discover_ai_modes
		self._write('recon', (
			'---\n'
			'allowed_actions: [query, follow_up, stop]\n'
			'max_iterations: 12\n'
			'---\n'
			'You are a recon assistant.\n${queries}\n'
		))
		modes = discover_ai_modes(self.tmp)
		self.assertIn('recon', modes)
		cfg = modes['recon']
		self.assertEqual(cfg['allowed_actions'], ['query', 'follow_up', 'stop'])
		self.assertEqual(cfg['max_iterations'], 12)
		self.assertIsInstance(cfg['system_prompt'], Template)
		# ${queries} include resolved into the prompt body
		self.assertIn('query_workspace', cfg['system_prompt'].template)

	def test_defaults_when_no_frontmatter(self):
		from secator.ai.prompts import discover_ai_modes, MODES
		self._write('plain', 'Just a prompt, no metadata.')
		cfg = discover_ai_modes(self.tmp)['plain']
		self.assertEqual(cfg['allowed_actions'], MODES['chat']['allowed_actions'])
		self.assertEqual(cfg['max_iterations'], MODES['chat']['max_iterations'])

	def test_unknown_actions_dropped(self):
		from secator.ai.prompts import discover_ai_modes
		self._write('weird', (
			'---\nallowed_actions: [query, not_a_real_action, stop]\n---\nBody.\n'
		))
		self.assertEqual(discover_ai_modes(self.tmp)['weird']['allowed_actions'], ['query', 'stop'])

	def test_broken_mode_skipped(self):
		from secator.ai.prompts import discover_ai_modes
		self._write('bad', '---\nallowed_actions: [not, closed\n---\nx')  # invalid YAML
		self._write('empty', '---\nmax_iterations: 3\n---\n   \n')         # empty body
		self._write('good', 'A valid prompt body.')
		modes = discover_ai_modes(self.tmp)
		self.assertIn('good', modes)
		self.assertNotIn('bad', modes)
		self.assertNotIn('empty', modes)

	def test_register_merges_and_get_mode_config(self):
		from secator.ai import prompts
		self._write('bugbounty', '---\nallowed_actions: [query, stop]\nmax_iterations: 7\n---\nHunt bugs.')
		try:
			registered = prompts.register_custom_modes(self.tmp)
			self.assertIn('bugbounty', registered)
			cfg = prompts.get_mode_config('bugbounty')
			self.assertEqual(cfg['max_iterations'], 7)
			self.assertEqual(cfg['allowed_actions'], ['query', 'stop'])
		finally:
			prompts.MODES.pop('bugbounty', None)

	def test_builtin_not_overridden_by_clash(self):
		from secator.ai import prompts
		self._write('chat', 'Malicious override attempt.')
		before = prompts.MODES['chat']
		registered = prompts.register_custom_modes(self.tmp)
		self.assertNotIn('chat', registered)
		self.assertIs(prompts.MODES['chat'], before)  # built-in untouched

	def test_no_dir_returns_empty(self):
		from secator.ai.prompts import discover_ai_modes
		self.assertEqual(discover_ai_modes(self.tmp / 'does-not-exist'), {})

	def test_custom_mode_with_tasks_gets_library_reference(self):
		from secator.ai import prompts
		self._write('pentest', '---\nallowed_actions: [task, workflow, query, stop]\n---\nRun tasks.\n${library_reference}\n')
		try:
			prompts.register_custom_modes(self.tmp)
			sp = prompts.get_system_prompt('pentest')
			# a task-enabled custom mode gets the library reference substituted (not left as ${...})
			self.assertNotIn('${library_reference}', sp)
			self.assertIn('<tasks>', sp)
		finally:
			prompts.MODES.pop('pentest', None)


if __name__ == '__main__':
	unittest.main()
