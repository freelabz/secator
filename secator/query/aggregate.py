"""Post-fetch ``--sort`` / ``--count`` / ``--uniq`` / ``--group`` aggregation of query / report
results: the per-type helpers, and the streaming aggregation over StreamView results (memory
bounded by the result size) with a single shared read on scan-per-query backends."""
from collections import Counter

from secator.query.format import _apply_format, _render_finding


def _sort_results_by_field(results, sort):
	"""Sort each type's findings by a field, in place. Numeric-aware (ints/floats sort naturally);
	a leading `-` sorts descending. Missing values sort last. Runs before --format, so `--sort port`
	orders the rows even when --format shows a different field. Backend-agnostic (post-fetch)."""
	field = sort.strip()
	reverse = field.startswith('-')
	if reverse:
		field = field[1:].strip()

	def _key(item):
		# Resolve the (dotted) field on dicts OR objects, so `--sort` also reaches attributes like
		# `_group_count` set by --group on the representative OutputType (dicts don't carry it).
		val = item
		for part in field.split('.'):
			if isinstance(val, dict):
				val = val.get(part)
			else:
				val = getattr(val, part, None)
			if val is None:
				break
		return val

	for _type, items in results.items():
		keyed = [(_key(it), it) for it in items]
		try:
			keyed.sort(key=lambda kv: (kv[0] is None, kv[0]), reverse=reverse)
		except TypeError:
			# Mixed/incomparable field types -> stable string ordering.
			keyed.sort(key=lambda kv: (kv[0] is None, str(kv[0])), reverse=reverse)
		results[_type] = [it for _, it in keyed]


def _aggregate_values(results, count=False, uniq=False, sort_given=False):
	"""Post-fetch aggregation of results, per type (backend-agnostic). `uniq` drops duplicate rows
	(first-seen order); `count` groups identical rows into ``"<count>  <value>"`` — most-frequent
	first by default, or in the sorted order the findings arrived in when --sort was given.

	Rows may be already-formatted strings (from --format) or raw finding dicts (no --format). For
	`uniq` the ORIGINAL item is kept (so raw findings still render richly via their OutputType, not
	as str(dict) JSON lines); the dedup key is the finding's display string."""
	out = {}
	for _type, values in results.items():
		if uniq and not count:
			seen = set()
			kept = []
			for v in values:
				key = v if isinstance(v, str) else _render_finding(v, _type)
				if key not in seen:
					seen.add(key)
					kept.append(v)   # keep original -> dicts render richly, strings stay strings
			out[_type] = kept
		elif count:
			svals = [v if isinstance(v, str) else _render_finding(v, _type) for v in values]
			items = list(Counter(svals).items())  # (value, count), first-seen insertion order
			if not sort_given:
				items.sort(key=lambda kv: kv[1], reverse=True)  # top-N: most frequent first
			width = max((len(str(c)) for _, c in items), default=1)
			out[_type] = [f'{str(c).rjust(width)}  {v}' for v, c in items]
		else:
			out[_type] = list(values)
	return out


def _num_key(s):
	"""Numeric-aware sort key for a rendered value string: numbers sort numerically (so '80' <
	'443'), non-numbers fall back to string order."""
	try:
		return (0, float(s))
	except (TypeError, ValueError):
		return (1, str(s))


class _StreamAggregator:
	"""Incremental --group / --count / --uniq / --sort aggregation of ONE finding type, fed one
	finding (raw dict or OutputType) at a time, so several types can be aggregated from a single
	stream. Peak memory is bounded by the RESULT size, not the number of findings — safe for 100k+:

	- --group: a FindingGrouper over raw dicts (memory ~ #groups); only the representatives are
	  rehydrated, then finished with the normal helpers.
	- --count / --uniq: collapse incrementally (Counter / seen-set), batching through _apply_format
	  only for the --format path; memory ~ #distinct values / #unique rows.
	- --sort alone (or --group on a type without a group key): a correct global sort needs the
	  whole set, so it materializes (``bounded`` is False).
	"""

	BATCH = 2000

	def __init__(self, _type, cls, fmt=None, sort=None, count=False, uniq=False, group=False, limit=0, rehydrate=True):
		from secator.query.utils import FindingGrouper
		self._type, self.fmt, self.sort, self.count, self.uniq, self.limit = _type, fmt, sort, count, uniq, limit
		self.rehydrate = rehydrate  # store dicts -> OutputType before --count/--uniq/--sort (not --group)
		self.grouper = None
		if group and cls is not None and getattr(cls, '_group_by', None):
			# Pass dataclass defaults so raw-dict grouping fills absent group-by fields (e.g. a tag
			# with no `category`) the same way rehydration would, keeping group keys/counts
			# identical to the object path.
			defaults = cls.field_defaults() if hasattr(cls, 'field_defaults') else None
			self.grouper = FindingGrouper(list(cls._group_by), getattr(cls, '_group_aggregate', None), defaults=defaults)
		self.bounded = self.grouper is not None or bool(count or uniq)
		self.counter, self.seen, self.kept, self.items, self.pending = Counter(), set(), [], [], []

	def add(self, item):
		if self.grouper is not None:
			self.grouper.add(item)  # raw dicts group natively; only representatives are rehydrated
			return
		self.pending.append(item)
		if len(self.pending) >= self.BATCH:
			self._flush()

	def _flush(self):
		from secator.output_types._base import load_output_types
		if not self.pending:
			return
		batch = list(load_output_types(self.pending)) if self.rehydrate else list(self.pending)
		self.pending.clear()
		if not (self.count or self.uniq):
			self.items.extend(batch)
			return
		_type = self._type
		if self.fmt:
			for v in _apply_format({_type: batch}, self.fmt).get(_type, []):
				if self.count:
					self.counter[v] += 1
				elif v not in self.seen:
					self.seen.add(v)
					self.kept.append(v)
		else:
			for it in batch:
				v = _render_finding(it, _type)
				if self.count:
					self.counter[v] += 1
				elif v not in self.seen:
					self.seen.add(v)
					self.kept.append(it)   # keep the finding -> renders richly, not str(dict)

	def _finish(self, items):
		_type, sort, limit = self._type, self.sort, self.limit
		res = {_type: items}
		if sort:
			_sort_results_by_field(res, sort)
		if self.fmt:
			res = _apply_format(res, self.fmt)
		if self.count or self.uniq:
			res = _aggregate_values(res, count=self.count, uniq=self.uniq, sort_given=bool(sort))
		rows = res.get(_type, [])  # _apply_format drops the type when there is nothing to format
		return rows[:limit] if limit else rows

	def result(self):
		sort, limit = self.sort, self.limit
		if self.grouper is not None:
			return self._finish(self.grouper.results())
		self._flush()
		if not (self.count or self.uniq):
			return self._finish(self.items)
		if self.uniq:
			kept = self.kept
			if sort:  # sort the COLLAPSED set (bounded by #unique), not the raw stream
				if self.fmt:
					kept.sort(key=_num_key, reverse=sort.strip().startswith('-'))
				else:
					res = {self._type: kept}
					_sort_results_by_field(res, sort)
					kept = res[self._type]
			return kept[:limit] if limit else kept
		items = list(self.counter.items())
		if sort:
			items.sort(key=lambda kv: _num_key(kv[0]), reverse=sort.strip().startswith('-'))
		else:
			items.sort(key=lambda kv: kv[1], reverse=True)   # most-frequent-first
		width = max((len(str(c)) for _, c in items), default=1)
		rows = [f'{str(c).rjust(width)}  {v}' for v, c in items]
		return rows[:limit] if limit else rows


def _aggregate_streamed(sv, _type, cls, fmt=None, sort=None, count=False, uniq=False, group=False, limit=0):
	"""Aggregate one type's StreamView (or any iterable of findings) with _StreamAggregator.

	Reads a StreamView's raw dicts (``iter_raw``) and rehydrates them in batches — for --group only
	the representatives; a plain iterable's items are aggregated as given. Iterates with
	``iter()``, not ``list(sv)``: list() asks a sized object for its len() first, which is a full
	count query on top of the read."""
	raw = hasattr(sv, 'iter_raw')
	agg = _StreamAggregator(
		_type, cls, fmt=fmt, sort=sort, count=count, uniq=uniq, group=group, limit=limit, rehydrate=raw)
	for item in (sv.iter_raw() if raw else iter(sv)):
		agg.add(item)
	return agg.result()


def _aggregate_views(views, query, type_map, fmt=None, sort=None, count=False, uniq=False, group=False, limit=0):
	"""Aggregate per-type results ``{type: StreamView | list}`` into ``{type: rows}``.

	An excluded type (an empty list, see Report.build) costs nothing. On a backend where each query
	is a full pass over the store (json), the queried types are read in ONE pass over ``query``
	and split by ``_type``, instead of one pass per type. A type whose aggregation materializes
	(--sort alone, --group without a group key) joins that pass only when its full item list is
	the output anyway (no --format / --limit); otherwise it keeps its own pass, so at most one such
	type is held in memory at a time — the same peak as before."""
	from secator.query._stream import StreamView, iter_types_raw
	aggs = {
		name: _StreamAggregator(
			name, type_map.get(name), fmt=fmt, sort=sort, count=count, uniq=uniq, group=group, limit=limit,
			rehydrate=hasattr(sv, 'iter_raw'))
		for name, sv in views.items()
	}
	streamed = [name for name, sv in views.items() if isinstance(sv, StreamView)]
	shared = []
	if query is not None and len(streamed) > 1:
		engine = views[streamed[0]]._engine
		if getattr(getattr(engine, 'backend', None), 'scan_per_query', False):
			shared = [name for name in streamed if aggs[name].bounded or not (fmt or limit)]
	if len(shared) > 1:
		for item in iter_types_raw(engine, query, shared):
			agg = aggs.get(item.get('_type')) if isinstance(item, dict) else None
			if agg is not None:
				agg.add(item)
	else:
		shared = []
	out = {}
	for name, sv in views.items():
		if name not in shared:
			for item in (sv.iter_raw() if hasattr(sv, 'iter_raw') else iter(sv)):
				aggs[name].add(item)
		out[name] = aggs[name].result()
	return out
