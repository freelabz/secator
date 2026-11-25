"""`secator x ai --show-map` prints the placeholder -> value map, read-only: no runner, no
model call, no file written. Scoped like a resume: the picked chat's map with --resume, else
every map of the workspace."""
import json
import re
from unittest import mock

import pytest

from secator.definitions import ADDONS_ENABLED

pytestmark = pytest.mark.skipif(not ADDONS_ENABLED.get('ai', False), reason='ai addon not installed')

WS = 'wsmap'


def _map_doc(session_id, values, workspace=WS):
	from secator.ai.encryption import SensitiveDataEncryptor
	enc = SensitiveDataEncryptor()
	for value in values:
		enc.encrypt(value)
	return {
		'_type': 'ai', 'ai_type': 'pii_map', 'content': '', '_uuid': f'pii-{session_id}', 'is_false_positive': False,
		'extra_data': {'pii_map': dict(enc.pii_map), 'hash_map': dict(enc.hash_map)},
		'_context': {'workspace_id': workspace, 'workspace_name': workspace, 'session_id': session_id}}


@pytest.fixture
def reports(tmp_path):
	from secator.config import CONFIG
	before = CONFIG.dirs.reports  # set by hand: a mock.patch of a pydantic config field does not restore cleanly
	CONFIG.dirs.reports = tmp_path
	docs = [
		_map_doc('s1', ['b.example.com', '10.0.0.1']),
		_map_doc('s2', ['a.example.com', 'b.example.com']),  # same placeholder as s1: shown once
		_map_doc('s3', ['other.example.com'], workspace='wsother')]
	for i, doc in enumerate(docs):
		folder = tmp_path / doc['_context']['workspace_name'] / 'tasks' / str(i)
		folder.mkdir(parents=True)
		(folder / 'results.ndjson').write_text(json.dumps(doc) + '\n')
	yield tmp_path
	CONFIG.dirs.reports = before


def _show_map(reports, *args, picked=None):
	"""Run the real CLI (``picked``: the chat the resume picker returns); return the printed table
	rows (placeholder, type, value) and the whole output."""
	import click.testing
	from secator.cli import cli
	from secator.rich import console
	files = sorted(reports.rglob('*'))
	with mock.patch('secator.tasks.ai.call_llm', side_effect=AssertionError('no LLM call expected')), \
	     mock.patch('secator.tasks.ai.show_session_picker', lambda sessions=None: picked):
		console.export_text(clear=True)
		result = click.testing.CliRunner().invoke(
			cli, ['x', 'ai', 'example.com', '--show-map', '-ws', WS, '--driver', 'json', *args], catch_exceptions=False)
		output = console.export_text(clear=True)
	assert result.exit_code == 0, result.output
	assert sorted(reports.rglob('*')) == files  # nothing written: no runner, no report
	rows = [line.split() for line in output.splitlines()]
	return [row for row in rows if len(row) == 3 and re.fullmatch(r'\[[A-Z0-9_]+:[0-9a-f]{12}\]', row[0])], output


def test_shows_every_map_of_the_workspace_deduped_and_sorted(reports):
	rows, _ = _show_map(reports)
	assert [(ph_type, value) for _, ph_type, value in rows] == [
		('HOST', 'a.example.com'), ('HOST', 'b.example.com'), ('IPV4', '10.0.0.1')]
	assert all(ph.startswith(f'[{ph_type}:') for ph, ph_type, _ in rows)


def test_resume_shows_the_picked_chat_map(reports):
	rows, _ = _show_map(reports, '--resume', picked={'store_session_id': 's1'})
	assert [value for _, _, value in rows] == ['b.example.com', '10.0.0.1']


def test_resume_of_a_chat_with_unknown_id_shows_the_workspace_maps(reports):
	rows, output = _show_map(reports, '--resume', picked={'store_session_id': ''})
	assert [value for _, _, value in rows] == ['a.example.com', 'b.example.com', '10.0.0.1']
	assert 'session id is unknown' in output


def test_cancelled_picker_shows_nothing(reports):
	rows, _ = _show_map(reports, '--resume', picked=None)
	assert rows == []
