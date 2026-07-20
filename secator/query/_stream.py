from secator.output_types._base import load_output_types


class StreamView:
	"""Lazy, streaming view over a run-scoped store query — the read-model for a run's findings.

	Self-contained over ``(engine, query, limit)``: iterating streams the backend cursor in batches
	(never materializes all N); ``len()`` is an indexed count; ``bool()`` is a cheap exists-check;
	``in`` is a keyed count query. Dicts are rehydrated to OutputType on the fly.
	"""
	def __init__(self, engine, query, batch_size=1000, limit=0):
		self._engine = engine
		self._query = query
		self._batch_size = batch_size
		self._limit = limit

	def __iter__(self):
		n = 0
		for batch in self._engine.iterate(self._query, self._batch_size):
			for item in load_output_types(batch):
				yield item
				n += 1
				if self._limit and n >= self._limit:
					return

	def __len__(self):
		n = self._engine.count(self._query)
		return min(n, self._limit) if self._limit else n

	def __bool__(self):
		# Exists-check by streaming — return on the first match instead of counting the whole set
		# (a bare count materializes on the json backend). Used by exporters' `if not items:` guard.
		for _ in self:
			return True
		return False

	def __contains__(self, item):
		# O(1) keyed exists-query on the compared fields (the same fields OutputType equality uses,
		# `_uuid` is compare=False), rather than streaming every record and scanning with `==`.
		from dataclasses import fields, is_dataclass
		if not is_dataclass(item):
			return any(x == item for x in self)
		q = {'_type': getattr(item, '_type', None)}
		q.update({f.name: getattr(item, f.name) for f in fields(item) if f.compare})
		return self._engine.count(q) > 0
