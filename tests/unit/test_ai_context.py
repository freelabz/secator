# tests/unit/test_ai_context.py
"""Unit tests for user-provided AI context files (`templates/ai/*.md`)."""
import pytest

from secator.definitions import ADDONS_ENABLED
from secator.config import CONFIG

pytestmark = pytest.mark.skipif(not ADDONS_ENABLED['ai'], reason='ai addon not installed')


@pytest.fixture
def ctx_dir(tmp_path, monkeypatch):
	"""Point CONFIG.dirs.templates at a temp dir and return its `ai/` subdir."""
	monkeypatch.setattr(CONFIG.dirs, 'templates', str(tmp_path))
	d = tmp_path / 'ai'
	d.mkdir()
	return d


def _write(d, name, content):
	(d / name).write_text(content)


def _load(mode, **kwargs):
	from secator.ai.context import load_context_blocks
	return load_context_blocks(mode, **kwargs)


# === frontmatter parsing ===

def test_no_frontmatter_is_global(ctx_dir):
	_write(ctx_dir, 'notes.md', 'Scope is 10.0.0.0/8.')
	assert _load('scan') == ['Scope is 10.0.0.0/8.']
	assert _load('exploit') == ['Scope is 10.0.0.0/8.']


def test_valid_frontmatter_is_stripped_from_body(ctx_dir):
	_write(ctx_dir, 'a.md', '---\nmodes: scan\n---\nHello body.')
	assert _load('scan') == ['Hello body.']


def test_malformed_frontmatter_is_skipped_not_fatal(ctx_dir):
	_write(ctx_dir, 'bad.md', '---\nmodes: [unterminated\n---\nbody')
	_write(ctx_dir, 'good.md', 'global note')
	# malformed file skipped, good file still loaded (fail-soft, no raise)
	assert _load('scan') == ['global note']


def test_non_mapping_frontmatter_is_skipped(ctx_dir):
	_write(ctx_dir, 'bad.md', '---\n- just\n- a\n- list\n---\nbody')
	assert _load('scan') == []


def test_empty_body_is_ignored(ctx_dir):
	_write(ctx_dir, 'empty.md', '---\nmodes: scan\n---\n   ')
	assert _load('scan') == []


def test_missing_dir_returns_empty(tmp_path, monkeypatch):
	monkeypatch.setattr(CONFIG.dirs, 'templates', str(tmp_path / 'nope'))
	assert _load('scan') == []


# === mode matching ===

def test_mode_omitted_matches_all(ctx_dir):
	_write(ctx_dir, 'a.md', '---\nworkspaces: w1\n---\nbody')
	assert _load('scan', workspace_name='w1') == ['body']
	assert _load('exploit', workspace_name='w1') == ['body']


def test_mode_string_matches_only_that_mode(ctx_dir):
	_write(ctx_dir, 'a.md', '---\nmodes: exploit\n---\nbody')
	assert _load('exploit') == ['body']
	assert _load('scan') == []


def test_mode_list_matches_any(ctx_dir):
	_write(ctx_dir, 'a.md', '---\nmodes: [scan, chat]\n---\nbody')
	assert _load('scan') == ['body']
	assert _load('chat') == ['body']
	assert _load('exploit') == []


# === workspace matching ===

def test_bare_string_matches_name_or_id(ctx_dir):
	_write(ctx_dir, 'a.md', '---\nworkspaces: acme\n---\nbody')
	assert _load('scan', workspace_name='acme') == ['body']
	assert _load('scan', workspace_name='other', workspace_id='acme') == ['body']
	assert _load('scan', workspace_name='other', workspace_id='xxx') == []


def test_explicit_name_match(ctx_dir):
	_write(ctx_dir, 'a.md', '---\nworkspaces:\n  - name: acme\n---\nbody')
	assert _load('scan', workspace_name='acme') == ['body']
	# an id equal to the value must NOT match when `name:` is forced
	assert _load('scan', workspace_name='other', workspace_id='acme') == []


def test_explicit_id_match(ctx_dir):
	_write(ctx_dir, 'a.md', '---\nworkspaces:\n  - id: "65f0"\n---\nbody')
	assert _load('scan', workspace_id='65f0') == ['body']
	assert _load('scan', workspace_name='65f0') == []


def test_regex_match_on_name(ctx_dir):
	_write(ctx_dir, 'a.md', '---\nworkspaces:\n  - regex: "^acme-.*$"\n---\nbody')
	assert _load('scan', workspace_name='acme-prod') == ['body']
	assert _load('scan', workspace_name='corp-acme') == []


def test_workspace_omitted_matches_all(ctx_dir):
	_write(ctx_dir, 'a.md', '---\nmodes: scan\n---\nbody')
	assert _load('scan', workspace_name='anything') == ['body']


# === deterministic ordering ===

def test_sorted_filename_ordering(ctx_dir):
	_write(ctx_dir, 'b.md', 'second')
	_write(ctx_dir, 'a.md', 'first')
	assert _load('scan') == ['first', 'second']


# === profile-forced include bypasses scope ===

def test_profile_include_bypasses_mode_and_workspace_scope(ctx_dir):
	# Scoped to exploit + workspace w1; we're in scan/w2 but force-include it.
	_write(ctx_dir, 'eng.md', '---\nmodes: exploit\nworkspaces: w1\n---\nforced body')
	assert _load('scan', workspace_name='w2') == []
	assert _load('scan', workspace_name='w2', includes=['eng.md']) == ['forced body']


def test_profile_include_accepts_path_basename(ctx_dir):
	_write(ctx_dir, 'eng.md', '---\nmodes: exploit\n---\nforced body')
	# a path is reduced to its basename for matching
	assert _load('scan', includes=['/some/dir/eng.md']) == ['forced body']
