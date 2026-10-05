"""Resolve a remote source (a git repository URL) to a local path.

A task that only accepts a local path (grype, trivy, gitleaks, ...) can't scan a repo
URL directly. This clones the repo shallowly to a local directory so the tool runs on
it. Tasks that handle remote URLs themselves (``URL`` in ``input_types``, e.g.
trufflehog) are left to do so. Optional token auth for private repos, kept out of the
clone's stored remote so a secret scanner won't flag it and it never persists.
"""
import os
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse, urlunparse

GIT_HOSTS = ('github.com', 'gitlab.com', 'bitbucket.org')


def is_git_url(value):
	"""True if ``value`` looks like a clonable git repository URL."""
	if not isinstance(value, str):
		return False
	s = value.strip()
	if s.startswith('git@') or s.startswith('ssh://'):
		return True
	if s.endswith('.git'):
		return True
	try:
		u = urlparse(s)
	except ValueError:
		return False
	if u.scheme in ('http', 'https') and u.hostname in GIT_HOSTS:
		parts = [p for p in u.path.split('/') if p]
		return len(parts) >= 2  # /owner/repo
	return False


def _repo_slug(url):
	name = re.sub(r'\.git$', '', url.rstrip('/').split('/')[-1])
	return re.sub(r'[^A-Za-z0-9._-]', '_', name) or 'repo'


def _split_token(url, token):
	"""Return (clone_url_with_token, clean_url) for an https URL."""
	u = urlparse(url)
	netloc = u.hostname + (f':{u.port}' if u.port else '')
	clean = urlunparse((u.scheme, netloc, u.path, '', '', ''))
	tokened = urlunparse((u.scheme, f'{token}@{netloc}', u.path, '', '', ''))
	return tokened, clean


def clone_git_repo(url, dest_folder, token=None, depth=1, timeout=300):
	"""Shallow-clone ``url`` into ``dest_folder`` and return the local path.

	Args:
		url (str): Repository URL (https, or ssh via an agent).
		dest_folder (str|Path): Parent directory the clone goes under.
		token (str|None): Access token for a private https repo.
		depth (int): Clone depth (shallow by default).
		timeout (int): Clone timeout in seconds.

	Returns:
		str: Local path to the cloned repository.
	"""
	dest_folder = Path(dest_folder)
	dest_folder.mkdir(parents=True, exist_ok=True)
	target = dest_folder / _repo_slug(url)
	if target.exists():
		shutil.rmtree(target, ignore_errors=True)

	clone_url, clean_url = url, url
	if token and url.startswith(('http://', 'https://')):
		clone_url, clean_url = _split_token(url, token)

	# GIT_TERMINAL_PROMPT=0 fails fast on a private repo with no/bad token instead of hanging.
	env = {**os.environ, 'GIT_TERMINAL_PROMPT': '0'}
	proc = subprocess.run(
		['git', 'clone', '--depth', str(depth), '--quiet', clone_url, str(target)],
		capture_output=True, text=True, timeout=timeout, env=env,
	)
	if proc.returncode != 0:
		err = (proc.stderr or '').strip()
		if token:
			err = err.replace(token, '***')  # never leak the token in an error
		raise RuntimeError(f'git clone failed ({err})')

	# Strip the token from the stored remote so a secret scanner won't flag it and it
	# never lingers in .git/config.
	if token:
		subprocess.run(['git', '-C', str(target), 'remote', 'set-url', 'origin', clean_url],
					   capture_output=True, text=True)
	return str(target)


def demo():  # pragma: no cover - a runnable check against a tiny public repo
	import tempfile
	assert is_git_url('https://github.com/octocat/Hello-World')
	assert is_git_url('git@github.com:octocat/Hello-World.git')
	assert is_git_url('https://ghe.acme.internal/org/repo.git')
	assert not is_git_url('/tmp/code')
	assert not is_git_url('https://example.com/not-a-repo')
	d = tempfile.mkdtemp()
	p = clone_git_repo('https://github.com/octocat/Hello-World.git', d)
	assert (Path(p) / '.git').is_dir(), p
	print('ok', p)


if __name__ == '__main__':
	demo()
