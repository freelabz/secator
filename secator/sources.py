"""Clone a git repository URL so a path-only task can scan it."""
import os
import re
import subprocess
from urllib.parse import urlparse


def is_git_url(value):
	"""True if ``value`` can only mean a git repository, so ``git clone`` can fetch it.

	This is a syntactic check (no network access) that accepts only unambiguous forms:

	- ``ssh://host/path`` and ``git://host/path`` URLs, and the scp-like ``user@host:path``;
	- ``git+https://host/path`` (or ``git+http://``): the ``git+`` prefix marks a web URL as a repository.

	A plain ``http(s)://`` URL is never a git URL, even when it ends in ``.git``: it may just be a web
	page that other tasks request. URLs with a password are refused, and so are ``git+http(s)`` URLs
	with any userinfo: inputs are printed and stored, and git would keep the credentials in the
	clone's remote URL. Private repositories use git's own credential configuration.
	"""
	if not isinstance(value, str):
		return False
	if re.fullmatch(r'[\w.-]+@[\w.-]+:(?!\d+$)[^/\s]\S*', value):
		return True
	try:
		url = urlparse(value)
	except ValueError:
		return False
	if url.password or not url.hostname or not url.path.strip('/'):
		return False
	if url.scheme in ('git+http', 'git+https'):
		return not url.username
	return url.scheme in ('ssh', 'git')


def clone_git_repo(url, folder, timeout=300):
	"""Shallow-clone the git URL ``url`` into ``folder`` and return the checkout path."""
	url = url.removeprefix('git+')
	path = os.path.join(folder, os.path.basename(url.rstrip('/')).removesuffix('.git') or 'repo')
	# GIT_TERMINAL_PROMPT=0: fail instead of waiting for credentials on stdin.
	subprocess.run(
		['git', 'clone', '--depth', '1', '--quiet', '--', url, path],
		check=True, capture_output=True, text=True, timeout=timeout, env={**os.environ, 'GIT_TERMINAL_PROMPT': '0'},
	)
	return path
