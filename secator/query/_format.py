"""Post-fetch ``--format`` rendering of query / report results (backend-agnostic)."""
import json
import re
from pathlib import Path

import click
from dotmap import DotMap

from secator.output_types import FINDING_TYPES
from secator.rich import console

FINDING_TYPES_LOWER = [c.__name__.lower() for c in FINDING_TYPES]


def _apply_format(results, fmt):
	"""Apply a --format string to report results, returning formatted strings grouped by type.

	Args:
		results (dict): Report results keyed by type name.
		fmt (str): Format spec(s), optionally pipe-separated per type.
			E.g. '{tag.match}-{tag.name}' or '{port.host}:{port.port} || vulnerability.matched_at'
			May also be a file path (< 255 chars, file must exist) to load the template from disk.

	Returns:
		dict: Results dict with items replaced by formatted strings (only matching types kept).
	"""
	fmt = fmt.strip()

	# Auto-detect format file: if fmt looks like a path and the file exists, load it.
	if len(fmt) < 255:
		p = Path(fmt)
		if p.is_file():
			try:
				fmt = p.read_text(encoding='utf-8')
			except (OSError, UnicodeDecodeError) as exc:
				raise click.UsageError(f'Could not read --format template file "{p}": {exc}') from exc

	# Unescape common escape sequences so CLI users can write \n, \t in their format strings.
	fmt = fmt.replace('\\n', '\n').replace('\\t', '\t')

	specs = [s.strip() for s in re.split(r'\s*\|\|\s*', fmt) if s.strip()]
	new_results = {}

	for spec in specs:
		_field_only = False
		if '{' in spec and '}' in spec:
			m = re.search(r'\{(\w+)\.', spec)
			if m and m.group(1) in results:
				# Brace-style with type.field dot notation: {url.host} {port.port}
				_type = m.group(1)
				_template = spec
			elif m and m.group(1) in FINDING_TYPES_LOWER:
				# Known output type referenced but not present in results — skip this spec.
				continue
			else:
				# Brace-style with direct field names or nested field access:
				# {url} {host} {status_code} or {extra_data.published}
				_field_only = True
				_type = None
				_template = spec
		else:
			parts = spec.split('.', 1)
			_type = parts[0]
			_field = parts[1] if len(parts) > 1 else None
			_template = '{' + _field + '}' if _field else None

		if _field_only:
			nonempty_types = [k for k, v in results.items() if v]
			if len(nonempty_types) != 1:
				console.print(f'[yellow]Warning: --format "{spec}" requires a single type in results, got: {nonempty_types}[/yellow]')  # noqa: E501
				continue
			_type = nonempty_types[0]
			items = results[_type]
			if not items:
				new_results[_type] = []
				continue
			formatted = []
			for item in items:
				d = item if isinstance(item, dict) else (item.toDict() if hasattr(item, 'toDict') else {})
				# Wrap nested dicts with DotMap to support dotted access (e.g. {extra_data.published})
				d_dotmaps = {k: DotMap(v) if isinstance(v, dict) else v for k, v in d.items()}
				try:
					value = _template.format(**d_dotmaps)
					if 'DotMap()' in str(value):
						continue
					formatted.append(value)
				except (KeyError, AttributeError):
					pass
			new_results[_type] = formatted
			continue

		if _type not in results:
			if _template is None:
				# The spec is a plain field name (no type prefix). If there is exactly one
				# non-empty type, fall back to field lookup on that type.
				nonempty_types = [k for k, v in results.items() if v]
				if len(nonempty_types) == 1:
					_actual_type = nonempty_types[0]
					items = results[_actual_type]
					formatted = []
					for item in items:
						d = item if isinstance(item, dict) else (item.toDict() if hasattr(item, 'toDict') else {})
						val = d.get(_type)
						if val is not None:
							formatted.append(str(val))
					new_results[_actual_type] = formatted
				elif nonempty_types:
					console.print(f'[yellow]Warning: --format type {_type!r} not found in results[/yellow]')
			elif _type not in FINDING_TYPES_LOWER:
				# Dotted field path (e.g. extra_data.published) where the first part is not a
				# known output type. Treat the whole spec as a nested field path on the single
				# non-empty result type, using DotMap for traversal.
				nonempty_types = [k for k, v in results.items() if v]
				if len(nonempty_types) == 1:
					_actual_type = nonempty_types[0]
					items = results[_actual_type]
					formatted = []
					path_parts = spec.split('.')
					for item in items:
						d = item if isinstance(item, dict) else (item.toDict() if hasattr(item, 'toDict') else {})
						val = DotMap(d)
						for part in path_parts:
							val = getattr(val, part, None)
							if val is None or (isinstance(val, DotMap) and not val):
								val = None
								break
						if val is not None:
							formatted.append(str(val))
					new_results[_actual_type] = formatted
			continue

		items = results[_type]
		if not items:
			new_results[_type] = []
			continue

		if _template:
			formatted = []
			is_brace_style = '{' in spec and '}' in spec
			for item in items:
				d = item if isinstance(item, dict) else (item.toDict() if hasattr(item, 'toDict') else {})
				try:
					# Brace-style ({type.field}): expose the item as a DotMap under the type key.
					# Dot-path style (type.field): wrap nested dict values as DotMap so that
					# templates like {extra_data.ttl} can resolve via attribute access.
					if is_brace_style:
						kwargs = {**d, _type: DotMap(d)}
					else:
						kwargs = {k: DotMap(v) if isinstance(v, dict) else v for k, v in d.items()}
					value = _template.format(**kwargs)
					# DotMap returns an empty DotMap() for missing nested paths; skip such items.
					if 'DotMap()' in str(value):
						continue
					formatted.append(value)
				except (KeyError, AttributeError):
					pass
			new_results[_type] = formatted
		else:
			# No field template. `_type` is a bare token that matched a result type name (e.g.
			# `-f port`). If that token is ALSO a field on the items, the user means the field
			# column — emit its value (parity with `-f port.port`). Otherwise fall back to each
			# OutputType's __str__ for a clean primary-field repr. Items from report.data['results']
			# may be raw dicts; reconstruct via OutputType.load() for the __str__ path.
			# Detect the field across the WHOLE result set (not just the first item), so a
			# heterogeneous type whose first item lacks the field still resolves the field values.
			_dicts = [item if isinstance(item, dict) else (item.toDict() if hasattr(item, 'toDict') else {})
					  for item in items]
			formatted = []
			if any(_type in d for d in _dicts):
				for d in _dicts:
					val = d.get(_type)
					if val is not None:
						formatted.append(str(val))
			else:
				# No matching field — render each finding via its OutputType (primary-field repr).
				formatted = [_render_finding(item, _type) for item in items]
			new_results[_type] = formatted

	return new_results


def _render_finding(item, _type):
	"""Render a finding to its display string — the OutputType's __str__ (what the console shows),
	falling back to JSON. Used when aggregating WITHOUT --format so raw finding dicts aren't shown
	as Python-dict / JSON reprs. Already-formatted strings pass through unchanged."""
	if not isinstance(item, dict):
		return str(item)
	otype_cls = {cls.get_name(): cls for cls in FINDING_TYPES}.get(_type)
	if otype_cls:
		try:
			return str(otype_cls.load(item))
		except Exception:
			return json.dumps(item)
	return json.dumps(item)
