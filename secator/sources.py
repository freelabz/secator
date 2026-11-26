"""Clone a git repository URL so a path task can scan it."""
import os
import re
import subprocess
from base64 import b64encode
from urllib.parse import urlparse


def is_git_url(value):
	"""True if ``value`` is a git repository URL that :func:`clone_git_repo` can clone.

	This is a syntactic check (no network access). It accepts:

	- ``ssh://host/path`` and ``git://host/path`` URLs, and the scp-like ``user@host:path``;
	- ``http(s)://host/path.git``, the usual form of a repository URL over http;
	- ``git+http(s)://host/path``: the ``git+`` prefix marks any web URL as a repository.

	Any other web URL (e.g. ``https://github.com/org/repo``) is not a git URL. No other transport
	(``file://``, ``ext::``, a local path, ...) is ever a git URL. URLs with a password are refused,
	and so are http(s) URLs with any userinfo: inputs are printed and stored, and git would keep the
	credentials in the clone's remote URL. Pass a token with the ``git_token`` run option instead.
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
	if url.scheme in ('ssh', 'git'):
		return True
	if url.username:
		return False
	return url.scheme in ('git+http', 'git+https') or (url.scheme in ('http', 'https') and url.path.endswith('.git'))


def clone_git_repo(url, folder, token=None, timeout=300):
	"""Shallow-clone the git URL ``url`` into ``folder`` and return the checkout path.

	git may only use the http, https, ssh and git transports (also for redirects and submodules)
	and does not follow http redirects. ``token`` authenticates an https clone: it goes to git as an
	``Authorization`` header in environment config scoped to the URL's origin, so it is not in the
	process arguments, the clone's ``.git/config`` or its remote URL, and it is never sent over
	http, ssh or git. A bare token is sent as ``x-access-token:<token>``; pass ``user:token`` to set
	the user name.
	"""
	url = url.removeprefix('git+')
	name = os.path.basename(url.rstrip('/')).removesuffix('.git')
	path = os.path.join(folder, name if name.strip('.') else 'repo')
	config = {'http.followRedirects': 'false'}
	origin = urlparse(url)
	if token and origin.scheme == 'https':
		credentials = b64encode((token if ':' in token else f'x-access-token:{token}').encode()).decode()
		config[f'http.https://{origin.netloc}/.extraHeader'] = f'Authorization: Basic {credentials}'
	# Never prompt (credentials, ssh host key): fail instead of waiting on stdin.
	env = {
		**os.environ, 'GIT_TERMINAL_PROMPT': '0', 'GIT_SSH_COMMAND': f"{os.environ.get('GIT_SSH_COMMAND', 'ssh')} -o BatchMode=yes",  # noqa: E501
		'GIT_ALLOW_PROTOCOL': 'http:https:ssh:git',
	}
	env['GIT_CONFIG_COUNT'] = str(len(config))
	for index, (key, value) in enumerate(config.items()):
		env[f'GIT_CONFIG_KEY_{index}'] = key
		env[f'GIT_CONFIG_VALUE_{index}'] = value
	subprocess.run(
		['git', 'clone', '--depth', '1', '--quiet', '--', url, path],
		check=True, capture_output=True, text=True, timeout=timeout, env=env, stdin=subprocess.DEVNULL,
	)
	return path
