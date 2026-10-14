"""Poll-source selection: StorePoller only for a reachable *shared* store (mongodb/api).

Filesystem stores (local/sqlite) are per-machine, so a dispatched run on those must fall back
to the Celery result-backend poll — QueryEngine.pollable_shared_store() encodes that decision.
"""
from secator.query import QueryEngine, SHARED_POLL_BACKENDS


class _StubBackend:
	def __init__(self, name, reachable, on_reach=None):
		self.name = name
		self._reachable = reachable
		self._on_reach = on_reach

	def is_reachable(self):
		if self._on_reach:
			self._on_reach()
		return self._reachable


def _engine_with(name, reachable, on_reach=None):
	# Bypass __init__/_select_backend — we only exercise the selection method.
	eng = QueryEngine.__new__(QueryEngine)
	eng.backend = _StubBackend(name, reachable, on_reach)
	return eng


def test_shared_store_reachable_uses_store_poll():
	assert _engine_with('mongodb', True).pollable_shared_store() is True
	assert _engine_with('api', True).pollable_shared_store() is True


def test_shared_store_unreachable_falls_back():
	assert _engine_with('mongodb', False).pollable_shared_store() is False
	assert _engine_with('api', False).pollable_shared_store() is False


def test_filesystem_store_never_polled_as_shared():
	# Even if a filesystem backend claimed reachable, it must not be used for the shared poll,
	# and is_reachable must NOT even be consulted (name gate short-circuits).
	called = []
	for name in ('local', 'sqlite'):
		eng = _engine_with(name, True, on_reach=lambda: called.append(name))
		assert eng.pollable_shared_store() is False
	assert called == [], 'is_reachable() should not be called for filesystem backends'


def test_shared_poll_backends_set():
	assert SHARED_POLL_BACKENDS == frozenset({'mongodb', 'api'})


if __name__ == '__main__':
	test_shared_store_reachable_uses_store_poll()
	test_shared_store_unreachable_falls_back()
	test_filesystem_store_never_polled_as_shared()
	test_shared_poll_backends_set()
	print('OK: poll-selection self-check passed')
