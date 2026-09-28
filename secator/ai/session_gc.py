"""Garbage-collect stale AI session work dirs.

The per-session work dir (``CONFIG.dirs.ai_sessions/<session_id>``) persists a
conversation's files (cloned PoCs, generated reports) across AI-task timeouts. On a
shared drive those dirs must be pruned eventually. This is a small, storage-agnostic
primitive a scheduled job (e.g. a Kubernetes CronJob) runs periodically:

``python -m secator.ai.session_gc --max-age-days 30``

It removes each session subdir whose most recent activity is older than the cutoff.
"""

import argparse
import shutil
import sys
from pathlib import Path
from time import time

from secator.config import CONFIG
from secator.utils import debug


def _last_activity(session_dir: Path) -> float:
	"""Most recent mtime of the session dir OR any of its immediate children.

	A dir's own mtime only bumps when entries are added/removed, so an in-place edit
	wouldn't refresh it — checking the top-level children too avoids pruning a session
	that's still being worked on. One level only (no deep walk): cheap and good enough
	for a day/30-day cadence."""
	newest = session_dir.stat().st_mtime
	try:
		for child in session_dir.iterdir():
			try:
				newest = max(newest, child.stat().st_mtime)
			except OSError:
				continue
	except OSError:
		pass
	return newest


def prune_ai_sessions(base=None, max_age_days=30, dry_run=False):
	"""Remove AI session dirs under ``base`` inactive for more than ``max_age_days``.

	Returns the list of removed (or, in dry-run, would-remove) session dir paths.
	Never raises on a single dir — a failure to stat/remove one is logged and skipped.
	"""
	base = Path(base or CONFIG.dirs.ai_sessions)
	if not base.is_dir():
		return []
	cutoff = time() - max_age_days * 86400
	removed = []
	for session_dir in base.iterdir():
		if not session_dir.is_dir():
			continue
		try:
			if _last_activity(session_dir) >= cutoff:
				continue
		except OSError as e:
			debug(f'skip {session_dir}: {e}', sub='ai.session_gc')
			continue
		removed.append(str(session_dir))
		if dry_run:
			continue
		try:
			shutil.rmtree(session_dir)
		except OSError as e:
			debug(f'failed to remove {session_dir}: {e}', sub='ai.session_gc')
			removed.pop()
	return removed


def main(argv=None):
	parser = argparse.ArgumentParser(prog='secator.ai.session_gc', description='Prune stale AI session work dirs.')
	parser.add_argument('--base', default=None, help='Sessions base dir (default: CONFIG.dirs.ai_sessions).')
	parser.add_argument('--max-age-days', type=float, default=30, help='Remove sessions inactive longer than this.')
	parser.add_argument('--dry-run', action='store_true', help='List what would be removed without deleting.')
	args = parser.parse_args(argv)
	removed = prune_ai_sessions(base=args.base, max_age_days=args.max_age_days, dry_run=args.dry_run)
	verb = 'Would remove' if args.dry_run else 'Removed'
	print(f'{verb} {len(removed)} stale AI session dir(s).')
	for path in removed:
		print(f'  {path}')
	return 0


if __name__ == '__main__':
	sys.exit(main())
