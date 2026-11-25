"""Quitting `secator x ai` (TUI) at the first prompt ends one runner: one report, in the run's
workspace, one end message. Real CLI, Textual app (headless) and ai task; no LLM call."""
import json
import shutil
import tempfile
import threading
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

import pytest

pytest.importorskip("textual")

from secator.definitions import ADDONS_ENABLED  # noqa: E402


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon required')
class TestAiTuiQuitReports(unittest.TestCase):

	def setUp(self):
		# Set and restore by hand: a mock.patch of a pydantic config field does not restore cleanly.
		from secator.config import CONFIG
		self.reports = Path(tempfile.mkdtemp())
		self._reports_before = CONFIG.dirs.reports
		CONFIG.dirs.reports = self.reports

	def tearDown(self):
		from secator.config import CONFIG
		CONFIG.dirs.reports = self._reports_before
		shutil.rmtree(self.reports, ignore_errors=True)

	def _quit_at_first_prompt(self, args):
		"""Return the {report path: status} written and the number of end messages."""
		import click.testing
		from secator.cli import cli
		from secator.rich import console
		from secator.tasks.ai import ai as AiTask
		from secator.tui.ai import AITUI
		asked, released = threading.Event(), threading.Event()
		app_run = AITUI.run
		threads_before = set(threading.enumerate())

		def wait_for_user(*args, **kwargs):
			asked.set()
			released.wait(30)

		def run_and_quit(app):
			def quit_app():
				asked.wait(30)
				app.call_from_thread(app.exit)
			threading.Thread(target=quit_app, daemon=True).start()
			app_run(app, headless=True)

		with ExitStack() as stack:
			for p in [
				mock.patch('secator.tasks.ai.call_llm', side_effect=AssertionError('no LLM call expected')),
				mock.patch.object(AiTask, '_verify_model', lambda self: iter(())),
				mock.patch.object(AiTask, '_prompt_and_redetect', wait_for_user),
				mock.patch('secator.ai.interactivity.TUIBackend.get_initial_prompt', wait_for_user),
				mock.patch('secator.tasks.ai.pick_session_via_backend', lambda backend, sessions, **k: sessions[0]),
				mock.patch.object(AITUI, 'run', run_and_quit),
				mock.patch.object(click.testing._NamedTextIOWrapper, 'isatty', return_value=True, create=True),
			]:
				stack.enter_context(p)
			console.export_text(clear=True)
			result = click.testing.CliRunner().invoke(
				cli, ['x', 'ai', 'example.com', '--model', 'gpt-4o', '--api-key', 'test', '--driver', 'json', *args],
				catch_exceptions=False)
			output = console.export_text(clear=True)
			# Let the abandoned runner thread end now, so it does not run on into later tests.
			released.set()
			for thread in set(threading.enumerate()) - threads_before:
				thread.join(10)
		self.assertEqual(result.exit_code, 0, result.output)
		reports = {
			str(p.relative_to(self.reports)): json.loads(p.read_text())['info'].get('status')
			for p in self.reports.rglob('report*.json')}
		return reports, output.count('Task ai finished with status')

	def test_quit_writes_one_report_in_the_workspace(self):
		reports, ends = self._quit_at_first_prompt(['-ws', 'wsB'])
		self.assertEqual(reports, {'wsB/tasks/0/report.json': 'REVOKED'})
		self.assertEqual(ends, 1)

	def test_resume_then_quit_ends_once_in_the_workspace(self):
		for ws in ('wsA', 'wsB'):
			folder = self.reports / ws / 'tasks' / '0'
			folder.mkdir(parents=True)
			(folder / 'history.json').write_text(json.dumps([{'role': 'user', 'content': 'hi'}]))
		reports, ends = self._quit_at_first_prompt(['-ws', 'wsA', '--resume'])
		self.assertEqual(reports.get('wsA/tasks/0/report.json'), 'REVOKED')  # the picked session's folder
		self.assertEqual([p for p in reports if not p.startswith('wsA/')], [])
		self.assertEqual(ends, 1)


if __name__ == '__main__':
	unittest.main()
