"""Report folder names must never break, or be interpreted by, the commands they end up in.

Two layers are covered:
- sanitize_folder_name only keeps a safe allowlist of characters;
- independently of that, every report path interpolated into a command is quoted, so even a reports folder with
  arbitrary characters (e.g. passed through the ``reports_folder`` run option) round-trips through shlex / the shell.
"""
import re
import shlex
import shutil
import tempfile
import unittest
import unittest.mock
from pathlib import Path

import pytest

from secator.definitions import OPT_PIPE_INPUT
from secator.runners import Command
from secator.tasks import arjun, ffuf, httpx, katana, nmap, nuclei
from secator.utils import get_workspace_folder_name, sanitize_folder_name

SPECIAL_CHARS = [
	"'", '"', '`', '$', '(', ')', ';', '&', '|', '<', '>', '*', '?', '[', ']', '{', '}', '!', '#', '~', '%', '\\',
	'^', '=', ',', ' ', '\t', '\n', 'é', '\U0001F600', '‮', ':', '@', '+',
]
SPECIAL_NAMES = [f'a{c}b' for c in SPECIAL_CHARS] + [
	"o'brien",
	'-leading',
	'--help',
	'.hidden',
	'..',
	'$(touch pwned)',
	'`touch pwned`',
	'a; touch pwned',
	'a | touch pwned',
	'a && touch pwned',
	'a\ntouch pwned',
]
SAFE_FOLDER = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9._]*$')


@pytest.mark.parametrize('name', SPECIAL_NAMES)
def test_sanitize_folder_name_allowlist(name):
	folder = sanitize_folder_name(name)
	assert SAFE_FOLDER.match(folder), folder
	assert not folder.startswith(('-', '.'))
	assert folder not in ('.', '..')


def test_sanitize_folder_name_examples():
	assert sanitize_folder_name("o'brien") == 'o_brien'
	assert sanitize_folder_name('my-workspace 2026') == 'my_workspace_2026'
	assert sanitize_folder_name('-leading') == 'leading'
	assert sanitize_folder_name('Été') == 'Ete'
	assert sanitize_folder_name('$(touch pwned)') == 'touch_pwned'
	assert sanitize_folder_name('!!!') == 'unnamed_folder'
	# Names that were already safe are unchanged
	for name in ('default', 'wscrossbackend', 'acme_2026', 'v1.2'):
		assert sanitize_folder_name(name) == name
	assert sanitize_folder_name('a-b', replace_hyphens=False) == 'a-b'


def test_sanitize_folder_name_legacy_rules():
	assert sanitize_folder_name("o'brien", strict=False) == "o'brien"


class TestWorkspaceFolderCompat(unittest.TestCase):

	def setUp(self):
		self.reports = Path(tempfile.mkdtemp(prefix='secator-test-reports-'))

	def tearDown(self):
		shutil.rmtree(self.reports, ignore_errors=True)

	def test_new_name_by_default(self):
		self.assertEqual(get_workspace_folder_name("o'brien", self.reports), 'o_brien')

	def test_existing_legacy_folder_is_reused(self):
		(self.reports / "o'brien").mkdir()
		self.assertEqual(get_workspace_folder_name("o'brien", self.reports), "o'brien")

	def test_strict_folder_wins_when_both_exist(self):
		(self.reports / "o'brien").mkdir()
		(self.reports / 'o_brien').mkdir()
		self.assertEqual(get_workspace_folder_name("o'brien", self.reports), 'o_brien')


def _reports_folder(base, name):
	folder = Path(base) / name / 'tasks' / '0'
	(folder / '.inputs').mkdir(parents=True)
	(folder / '.outputs').mkdir()
	return folder


TASKS = [
	(httpx, {'store_responses': True}),
	(nuclei, {'store_responses': True, 'logs': True}),
	(katana, {'store_responses': True}),
	(arjun, {}),
	(nmap, {}),
	(ffuf, {}),
]
CMD_NAMES = [f'a{c}b' for c in SPECIAL_CHARS if c not in ('\n',)] + [
	"o'brien", '-leading', '$(touch pwned)', '`touch pwned`', 'a; touch pwned', 'a\ntouch pwned']


@pytest.mark.parametrize('name', CMD_NAMES)
@pytest.mark.parametrize('task_cls,opts', TASKS, ids=lambda x: getattr(x, '__name__', ''))
@pytest.mark.parametrize('targets', [['http://example.com/?q=1'], ['http://example.com/?q=1', 'http://scanme.nmap.org/']])  # noqa: E501
def test_report_paths_are_quoted_in_cmd(tmp_path, name, task_cls, opts, targets):
	folder = _reports_folder(tmp_path, name)
	task = task_cls(targets, reports_folder=str(folder), sync=True, **opts)
	args = shlex.split(task.cmd)  # must not raise
	path_args = [a for a in args if str(tmp_path) in a]
	for arg in path_args:
		assert arg.startswith(str(folder)), (arg, task.cmd)
	if task.inputs_path:
		assert task.inputs_path in args


@pytest.mark.parametrize('name', ['$(touch pwned)', '`touch pwned`', 'a; touch pwned', 'a | touch pwned', 'a\ntouch pwned', "o'brien"])  # noqa: E501
def test_piped_input_file_is_not_interpreted_by_shell(tmp_path, name):
	"""Run a real piped command: the reports folder name must stay literal (no command substitution / chaining)."""
	class PipeCatCmd(Command):
		cmd = 'cat'
		file_flag = OPT_PIPE_INPUT
		input_chunk_size = -1

	folder = _reports_folder(tmp_path, name)
	targets = ['one', 'two']
	with unittest.mock.patch('secator.runners.task.Task.get_task_class', return_value=PipeCatCmd):
		task = PipeCatCmd(targets, reports_folder=str(folder), sync=True)
	assert task.shell
	list(task.run())
	assert not task.errors, task.errors
	assert task.output.split('\n') == targets
	assert not list(Path(task.cwd or folder).rglob('pwned'))
	assert not list(tmp_path.rglob('pwned'))
	assert not (Path.cwd() / 'pwned').exists()
