"""Pluggable template-source storage.

Materializes a *pinned, vetted* template set into the local templates root
(:data:`CONFIG.dirs.templates`) so a task that consumes a directory of templates
(e.g. ``nuclei -t <dir>``) can point at a stable, verified on-disk path.

The source of a template set is given as a :class:`TemplateSourceRef`: a storage
reference (a git clone URL or a storage URI) plus a pinned commit SHA. Core
materializes the referenced tree into ``CONFIG.dirs.templates/<name>`` and
verifies the pin before handing back the local path.

Storage backends are **pluggable**, mirroring the optional-GCS pattern used
elsewhere in secator: the backend is chosen from the reference and the active
config. Two backends ship today:

- ``git`` (default, no extra config): ``git clone`` the URL, ``git checkout``
the SHA, and verify ``HEAD == sha``. Works on any filesystem / on-prem.
- ``gcs``: fetch a SHA-named tarball of the vetted tree from a Google Cloud
Storage bucket (used only when the GCS addon is configured). The object name
carries the SHA, so the pin is the object identity.

Additional backends (other object stores for on-prem) can register via
:func:`register_backend` without touching callers.

Nothing here references any hosted service, deployment, or UI — it is a generic
mechanism: *given a pinned reference, produce a verified local template dir*.
"""

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict

from secator.config import CONFIG
from secator.rich import console
from secator.utils import debug

#: A 40-hex git commit SHA. Branch/tag refs are intentionally rejected: only an
#: immutable, fully-qualified commit is a valid pin.
SHA_RE = re.compile(r'^[0-9a-f]{40}$')

#: A template-set *name* becomes an on-disk folder under the templates root, so
#: it must be a safe slug (no path separators, no traversal).
NAME_RE = re.compile(r'^[a-z0-9][a-z0-9_-]{0,63}$')


class TemplateSourceError(Exception):
	"""Raised when a template set cannot be materialized or its pin verified."""
	pass


@dataclass
class TemplateSourceRef:
	"""A reference to a vetted, pinned template set.

	Attributes:
		name (str): Stable slug; becomes the on-disk folder name under the
			templates root and the handle callers point ``-t`` at.
		url (str): Storage reference — a git clone URL (``https://…``) or a
			storage URI (``gs://bucket/prefix``). The scheme selects the backend.
		sha (str): Pinned 40-hex commit SHA. The exact tree that was vetted.
		subdir (str): Optional path *within* the set to expose as the template
			dir (lets one source hold several sets). Must stay inside the tree.
	"""
	name: str
	url: str
	sha: str
	subdir: str = ''

	def __post_init__(self):
		if not NAME_RE.match(self.name or ''):
			raise TemplateSourceError(
				f'invalid template set name {self.name!r}: must be a slug matching {NAME_RE.pattern}'
			)
		if not SHA_RE.match((self.sha or '').lower()):
			raise TemplateSourceError(
				f'invalid pin {self.sha!r} for set {self.name!r}: a full 40-hex commit SHA is required '
				'(branch/tag refs are not accepted)'
			)
		self.sha = self.sha.lower()
		# Reject traversal in subdir; keep it relative and inside the tree.
		if self.subdir:
			sub = Path(self.subdir)
			if sub.is_absolute() or '..' in sub.parts:
				raise TemplateSourceError(f'invalid subdir {self.subdir!r} for set {self.name!r}')


# ──────────────────────────────────────────────────────────────────────────────
# Backend registry
# ──────────────────────────────────────────────────────────────────────────────

#: A backend materializes a ref's *tree* into ``dest`` (a fresh dir) at the
#: pinned SHA, raising TemplateSourceError on any pin mismatch / fetch failure.
Backend = Callable[[TemplateSourceRef, Path], None]

_BACKENDS: Dict[str, Backend] = {}


def register_backend(scheme: str, backend: Backend) -> None:
	"""Register a storage backend for a URL scheme (e.g. ``gs``, ``https``)."""
	_BACKENDS[scheme] = backend


def _scheme_of(url: str) -> str:
	return url.split('://', 1)[0].lower() if '://' in url else ''


def select_backend(ref: TemplateSourceRef) -> Backend:
	"""Pick the backend for a ref from its scheme and the active config.

	Mirrors the optional-GCS pattern: a ``gs://`` ref uses the GCS backend only
	when the GCS addon is configured; everything else (and ``gs://`` without the
	addon) falls back to the default git/local-fs backend.
	"""
	scheme = _scheme_of(ref.url)
	if scheme == 'gs':
		if CONFIG.addons.gcs.bucket_name:
			return _BACKENDS['gs']
		raise TemplateSourceError(
			f'template set {ref.name!r} references a gs:// source but the GCS addon is not configured '
			'(addons.gcs.bucket_name is empty)'
		)
	return _BACKENDS.get(scheme, _BACKENDS['git-default'])


# ──────────────────────────────────────────────────────────────────────────────
# Default backend: git clone + checkout + verify (local filesystem)
# ──────────────────────────────────────────────────────────────────────────────

# SECURITY: a template-source URL is remote/untrusted input. git's `ext::` transport
# runs an arbitrary shell command and `file://`/local transports can read the host
# filesystem — both are RCE/LFI vectors when a URL is attacker-influenced. Disable
# every non-network transport on every git invocation (config overrides survive into
# sub-processes git spawns for a given transport) and pin the allow-list via
# GIT_ALLOW_PROTOCOL so only http(s)/ssh/git remote transports can ever be used.
_GIT_TRANSPORT_HARDENING = [
	'-c', 'protocol.ext.allow=never',
	'-c', 'protocol.file.allow=never',
	'-c', 'protocol.fd.allow=never',
]
_GIT_ALLOW_PROTOCOL = 'https:http:ssh:git'

# Cap every git invocation: a hostile/slow remote (or a prompt git can't suppress)
# must not hang the worker indefinitely. Overridable for very large sources.
_GIT_TIMEOUT = int(os.environ.get('SECATOR_TEMPLATE_GIT_TIMEOUT', '300'))


def _run_git(args, cwd=None):
	env = dict(os.environ, GIT_ALLOW_PROTOCOL=_GIT_ALLOW_PROTOCOL, GIT_TERMINAL_PROMPT='0')
	try:
		return subprocess.run(
			['git', *_GIT_TRANSPORT_HARDENING, *args], cwd=cwd, check=True, env=env,
			stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=_GIT_TIMEOUT,
		)
	except FileNotFoundError:
		raise TemplateSourceError('git is not installed; required to materialize a git template source')
	except subprocess.TimeoutExpired:
		raise TemplateSourceError(f'git {" ".join(args)} timed out after {_GIT_TIMEOUT}s')
	except subprocess.CalledProcessError as e:
		raise TemplateSourceError(f'git {" ".join(args)} failed: {e.stderr.strip() or e.returncode}')


# A nuclei template set is YAML/JSON data only. A materialized tree is scanned at
# import time for external tasks/drivers — any `.py` under the templates root is
# exec'd — so a stray `.py` in a template source is remote-code-execution on the
# worker. Refuse to materialize a set that carries any `.py`. We also refuse symlinks
# outright: a symlink can escape the set root (link to /etc, to another task file,
# or to a `.py` outside the tree that discovery would still exec).
_MAX_TEMPLATE_SET_BYTES = int(os.environ.get('SECATOR_TEMPLATE_SET_MAX_BYTES', str(512 * 1024 * 1024)))


def _reject_unsafe_tree(root: Path, name: str) -> None:
	"""Reject a materialized tree containing symlinks or `.py` files (RCE guard)."""
	root = root.resolve()
	for p in root.rglob('*'):
		if p.is_symlink():
			raise TemplateSourceError(
				f'template set {name!r} contains a symlink ({p.relative_to(root)}); refusing (symlinks are not allowed)'
			)
		if p.is_file() and p.suffix.lower() == '.py':
			raise TemplateSourceError(
				f'template set {name!r} contains a Python file ({p.relative_to(root)}); a template set must be '
				'data only (YAML) — refusing to materialize executable code'
			)


def _enforce_size_cap(root: Path, name: str) -> None:
	"""Reject a materialized tree whose on-disk size exceeds the cap (zip/clone bomb)."""
	total = 0
	for p in root.rglob('*'):
		if p.is_symlink():
			continue  # size of the link target is irrelevant; symlinks are rejected separately
		if p.is_file():
			try:
				total += p.stat().st_size
			except OSError:
				continue
			if total > _MAX_TEMPLATE_SET_BYTES:
				raise TemplateSourceError(
					f'template set {name!r} exceeds the size cap ({_MAX_TEMPLATE_SET_BYTES} bytes)'
				)


def git_backend(ref: TemplateSourceRef, dest: Path) -> None:
	"""Clone ``ref.url``, check out ``ref.sha``, and verify ``HEAD == sha``.

	The whole operation happens on the local filesystem; no object store is
	involved. This is the default backend and the on-prem path.
	"""
	# DoS guard: a blobless partial clone pulls only the commit graph up front, so a
	# repo with a huge history can't balloon the clone; blobs arrive only on checkout
	# of the pinned tree, which is then size-capped below.
	_run_git(['clone', '--quiet', '--no-checkout', '--filter=blob:none', ref.url, str(dest)])
	# Fetch the exact commit (works even if it is not the branch tip), then check out.
	_run_git(['fetch', '--quiet', '--filter=blob:none', 'origin', ref.sha], cwd=dest)
	_run_git(['checkout', '--quiet', ref.sha], cwd=dest)
	head = _run_git(['rev-parse', 'HEAD'], cwd=dest).stdout.strip().lower()
	if head != ref.sha:
		raise TemplateSourceError(f'pin verification failed for {ref.name!r}: HEAD {head} != pinned {ref.sha}')
	shutil.rmtree(dest / '.git', ignore_errors=True)
	_enforce_size_cap(dest, ref.name)


register_backend('git-default', git_backend)
register_backend('https', git_backend)
register_backend('http', git_backend)
register_backend('git', git_backend)
register_backend('ssh', git_backend)


# ──────────────────────────────────────────────────────────────────────────────
# Optional backend: GCS tarball fetch (SHA-named object = the pin)
# ──────────────────────────────────────────────────────────────────────────────

def gcs_backend(ref: TemplateSourceRef, dest: Path) -> None:
	"""Fetch a pinned tarball from GCS and unpack it into ``dest``.

	The ref url is ``gs://<bucket>/<prefix>``; the object fetched is
	``<prefix>/<name>-<sha>.tar.gz``. Because the SHA is part of the object
	name, the object identity *is* the pin — fetching a different SHA fetches a
	different object. Used only when the GCS addon is configured.
	"""
	from secator.hooks.gcs import download_blob
	_, _, rest = ref.url.partition('gs://')
	bucket, _, prefix = rest.partition('/')
	blob_name = f'{prefix.rstrip("/") + "/" if prefix else ""}{ref.name}-{ref.sha}.tar.gz'
	dest.mkdir(parents=True, exist_ok=True)
	tarball = dest.parent / f'.{ref.name}-{ref.sha}.tar.gz'
	try:
		download_blob(bucket, blob_name, str(tarball))
		import tarfile
		with tarfile.open(tarball) as tf:
			base = dest.resolve()
			total = 0
			for member in tf.getmembers():
				# Reject symlink/hardlink members outright — they can point outside the
				# tree (RCE/LFI) and symlinks are not valid template data anyway.
				if member.issym() or member.islnk():
					raise TemplateSourceError(
						f'unsafe link member in tarball for {ref.name!r}: {member.name}'
					)
				# Guard against path traversal (member resolving outside base).
				target = (dest / member.name).resolve()
				if target != base and base not in target.parents:
					raise TemplateSourceError(f'unsafe path in tarball for {ref.name!r}: {member.name}')
				# Reject executable code: a template set is YAML data only.
				if member.isfile() and member.name.lower().endswith('.py'):
					raise TemplateSourceError(
						f'tarball for {ref.name!r} contains a Python file ({member.name}); refusing'
					)
				# Decompression-bomb guard: cap total uncompressed size.
				total += max(member.size, 0)
				if total > _MAX_TEMPLATE_SET_BYTES:
					raise TemplateSourceError(
						f'tarball for {ref.name!r} exceeds the size cap ({_MAX_TEMPLATE_SET_BYTES} bytes)'
					)
			tf.extractall(dest)
	finally:
		tarball.unlink(missing_ok=True)
	_reject_unsafe_tree(dest, ref.name)


register_backend('gs', gcs_backend)


# ──────────────────────────────────────────────────────────────────────────────
# Public entrypoint
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class MaterializeResult:
	ref: TemplateSourceRef
	path: Path
	refreshed: bool = False
	backend: str = ''


def _templates_root() -> Path:
	root = Path(CONFIG.dirs.templates)
	root.mkdir(parents=True, exist_ok=True)
	return root


def _pin_marker(target: Path) -> Path:
	return target / '.secator-template-pin'


def materialize_template_source(ref: TemplateSourceRef, force: bool = False) -> MaterializeResult:
	"""Materialize a pinned template set into ``CONFIG.dirs.templates/<name>``.

	Idempotent: if the set is already present at the pinned SHA, the existing
	directory is reused (unless ``force``). Otherwise the set is (re)fetched via
	the backend selected from the ref, into a temp dir, pin-verified, then
	atomically swapped into place. Returns the verified local path to point a
	task's templates option at (plus ``ref.subdir`` when set).

	Raises:
		TemplateSourceError: on invalid ref, backend failure, or pin mismatch.
	"""
	root = _templates_root()
	target = root / ref.name
	marker = _pin_marker(target)

	if target.exists() and marker.exists() and not force:
		if marker.read_text().strip().lower() == ref.sha:
			# The set root already holds the vetted templates (subdir promoted at
			# materialization), so point straight at it — no residual subdir join.
			debug(f'reusing {ref.name} @ {ref.sha}', sub='template_source')
			return MaterializeResult(ref=ref, path=target, refreshed=False, backend=_scheme_of(ref.url) or 'git')

	backend = select_backend(ref)
	staging = root / f'.{ref.name}.{ref.sha}.staging'
	shutil.rmtree(staging, ignore_errors=True)
	try:
		backend(ref, staging)
		# When a subdir is requested, that subdir IS the template set: promote only
		# its contents to the set root. The templates root is scanned at import time
		# for external tasks/drivers (any `.py` under it is loaded), so a source repo
		# that carries non-template files alongside the templates (tooling, a `lab/`,
		# helper scripts) must not land under the templates root — only the vetted
		# subdir does. Materializing the whole tree would expose those files to task
		# discovery. The on-disk set is therefore exactly the subdir, so callers point
		# `-t` at the set root (no residual subdir component).
		if ref.subdir:
			sub = staging / ref.subdir
			# Reject symlink escape: the requested subdir (and every component of its
			# path) must be a real directory inside the staged tree, never a symlink
			# that could promote a directory from outside the vetted tree.
			staging_base = staging.resolve()
			resolved_sub = sub.resolve()
			if resolved_sub != staging_base and staging_base not in resolved_sub.parents:
				raise TemplateSourceError(
					f'subdir {ref.subdir!r} for set {ref.name!r} escapes the template set root'
				)
			if sub.is_symlink() or not sub.is_dir():
				raise TemplateSourceError(f'subdir {ref.subdir!r} not found in template set {ref.name!r}')
			promoted = root / f'.{ref.name}.{ref.sha}.promoted'
			shutil.rmtree(promoted, ignore_errors=True)
			sub.rename(promoted)
			shutil.rmtree(staging, ignore_errors=True)
			staging = promoted
		# Final guard on the exact tree that will land under the templates root: no
		# symlinks, no `.py` (import-time RCE), and within the size cap.
		_reject_unsafe_tree(staging, ref.name)
		_enforce_size_cap(staging, ref.name)
		_pin_marker(staging).write_text(ref.sha)
		# Atomic-ish swap: remove old, move staging into place.
		shutil.rmtree(target, ignore_errors=True)
		staging.rename(target)
	finally:
		shutil.rmtree(staging, ignore_errors=True)

	console.print(f':inbox_tray: Materialized template set [bold]{ref.name}[/] @ {ref.sha[:10]}')
	# The set root now holds the vetted templates directly (subdir already promoted).
	return MaterializeResult(ref=ref, path=target, refreshed=True, backend=_scheme_of(ref.url) or 'git')


def ref_from_dict(data: dict) -> TemplateSourceRef:
	"""Build a :class:`TemplateSourceRef` from a plain dict (e.g. a run_opt)."""
	return TemplateSourceRef(
		name=data.get('name') or data.get('label') or '',
		url=data.get('url', ''),
		sha=data.get('sha', ''),
		subdir=data.get('subdir', '') or '',
	)
