# secator/workspace_migrate.py
#
# Copy a workspace from one driver to another (``secator workspace migrate``).
#
# Reads go through the source QueryEngine (findings by their latest record, runners, notes).
# Writes go through the destination driver's own hooks, called on a runner-like object rebuilt
# from each stored runner doc (``StoredRunner``), so every driver writes migrated data exactly as
# it writes a live run: same ids, same layout, same store-side defaults.
#
# Ids: every runner / chat id of the source maps to a new id at the destination. A fresh id is
# given first, and the driver may replace it on write (mongodb mints ObjectIds, the api driver
# adopts the remote id): the ids it ends up with are recorded, and a runner whose links changed
# after it was written (e.g. a chat's session_id) is written again.
#
# Re-runs: each migrated doc records its source id in ``(_)context.migrated_from``. A re-run maps
# each source doc to its migrated copy and writes the same doc again instead of a new one.

import hashlib
import uuid
from collections import Counter, defaultdict
from pathlib import Path

import orjson
from dotmap import DotMap

from secator.output_types import Warning
from secator.output_types._base import load_output_types
from secator.query import QueryEngine
from secator.rich import console
from secator.runners import Runner, Scan, Task, Workflow
from secator.utils import import_dynamic, to_datetime

# Context keys holding a runner or chat id, relinked to the destination's ids.
ID_KEYS = ('scan_id', 'workflow_id', 'task_id', 'task_chunk_id', 'session_id')
RUNNER_CLASSES = {'scan': Scan, 'workflow': Workflow, 'task': Task}


def hooks_driver(driver):
	"""Driver whose hooks write to the given query backend ('local' is the json driver)."""
	return 'json' if driver == 'local' else driver


def resolve_workspace_id(driver, name, create=False):
	"""The id runs store as ``context.workspace_id``: the name, except on the api driver, which
	keys workspaces by their remote id (None if it does not exist and ``create`` is False)."""
	if driver != 'api':
		return name
	from secator.hooks.api import create_workspace, resolve_workspace
	if create:
		return create_workspace(name)[1]
	try:
		return resolve_workspace(name)[0]
	except Exception as e:
		if 'not found in remote API' not in str(e):
			raise
		return None


def runner_key(context, rtype):
	"""A runner's own id: its chunk id when it has one, else its ``{type}_id``."""
	return context.get(f'{rtype}_chunk_id') or context.get(f'{rtype}_id')


def note_id(note):
	"""A note's id in its store, or a hash of its content for a store that keeps none (json)."""
	if note.get('_id') or note.get('_uuid'):
		return str(note.get('_id') or note.get('_uuid'))
	body = {k: v for k, v in note.items() if k != '_context'}
	return hashlib.sha256(orjson.dumps(body, default=str, option=orjson.OPT_SORT_KEYS)).hexdigest()


class StoredRunner:
	"""A stored runner doc exposing what the driver hooks read from a live runner (config,
	context, toDict(), reports_folder...), so they can write it like a run they persist."""

	print_reports_message = False
	fqn = Runner.fqn

	def __init__(self, doc, workspace_name, parent=None, reports_folder=None):
		self.doc = doc
		self.config = DotMap(doc['config'])
		self.context = doc['context']
		self.name = self.unique_name = doc.get('name') or ''
		self.status = doc.get('status')
		self.has_parent = bool(doc.get('has_parent'))
		self.chunk = doc.get('chunk')
		self.last_updated_db = doc.get('last_updated_db')
		self.workspace_name = workspace_name
		self.parent = parent
		self._reports_folder = reports_folder

	@property
	def reports_folder(self):
		"""Report dir (read by the json driver only): a child shares its parent's, a root claims
		the next free dir of the workspace (Runner.reports_folder)."""
		if self.parent:
			return self.parent.reports_folder
		return Runner.reports_folder.fget(self)

	def debug(self, *args, **kwargs):
		pass

	def toDict(self):
		return {**self.doc, 'context': self.context}

	def add_result(self, item):
		"""Hooks report store limits (e.g. a doc too large to store) as a result."""
		console.print(item)


class WorkspaceMigration:
	"""Copy the workspace ``name`` of the ``src`` query backend to ``dst`` (as ``new_name``)."""

	def __init__(self, name, src, dst, new_name=None, keep_status=False):
		self.name, self.src, self.dst = name, src, dst
		self.new_name = new_name or name
		self.keep_status = keep_status
		self.src_ws = resolve_workspace_id(src, name)
		if not self.src_ws:
			raise ValueError(f'Workspace "{name}" not found on the {src} driver.')
		self.dst_ws = resolve_workspace_id(dst, self.new_name)
		self.ids = {}    # source runner / chat id -> destination id
		self.uuids = {}  # source finding _uuid -> destination _uuid
		self.runs = {}   # source runner id -> StoredRunner
		self.failed = 0
		self._read_source()
		self._read_destination()

	@staticmethod
	def _engine(driver, ws_id, ws_name):
		return QueryEngine(ws_id, context={'drivers': [hooks_driver(driver)], 'workspace_name': ws_name})

	# ---------- read ----------

	def _read_source(self):
		engine = self._engine(self.src, self.src_ws, self.name)
		self.findings = {}
		for rec in engine.search({}, scope_only=True, include_internal=True):
			if rec.get('_uuid') or rec.get('_id'):
				self.findings[str(rec.get('_uuid') or rec.get('_id'))] = rec
		# The same runner can be stored twice (e.g. as a child report and as its own report): keep
		# the most complete copy.
		best = {}
		for doc in engine.list_runners(workspace_id=self.src_ws):
			rtype = (doc.get('config') or {}).get('type') or str(doc.get('_type', '')).removesuffix('s')
			key = runner_key(doc.get('context') or {}, rtype)
			if rtype not in RUNNER_CLASSES or not key:
				console.print(Warning(message=f'Skipping runner "{doc.get("name")}" with no id.'))
				continue
			rank = (bool(doc.get('done')), doc.get('last_updated_db') or 0, doc.get('elapsed') or 0)
			if key not in best or rank > best[key][0]:
				best[key] = (rank, {**doc, 'config': {**(doc.get('config') or {}), 'type': rtype}})
		self.runners = {key: doc for key, (_, doc) in best.items()}
		self.rebuilt = self._rebuild_ai_runners()
		self.notes = engine.list_notes()

	def _rebuild_ai_runners(self):
		"""Rebuild the runner of an ai chat whose runner doc is gone (e.g. a later chat reused its
		report dir and overwrote it) from the chat's own findings."""
		orphans = defaultdict(list)
		for rec in self.findings.values():
			ctx = rec.get('_context') or {}
			key = ctx.get('task_id')
			if (rec.get('_source') == 'ai' and key and key not in self.runners
					and not any(ctx.get(k) for k in ('task_chunk_id', 'workflow_id', 'scan_id'))):
				orphans[key].append(rec)
		config = next((r['config'] for r in self.runners.values() if r.get('name') == 'ai'), {'type': 'task', 'name': 'ai'})
		for key, recs in orphans.items():
			recs.sort(key=lambda r: r.get('_timestamp') or 0)
			first, last = recs[0], recs[-1]
			ais = [r for r in recs if r.get('_type') == 'ai']
			start, end = first.get('_timestamp') or 0, last.get('_timestamp') or 0
			self.runners[key] = {
				'name': 'ai', 'status': 'FAILURE' if last.get('_type') == 'error' else 'SUCCESS',
				'targets': [], 'start_time': to_datetime(start), 'end_time': to_datetime(end), 'elapsed': end - start,
				'run_opts': {
					'prompt': next((r.get('content') for r in ais if r.get('ai_type') == 'prompt'), ''),
					'model': next((r.get('model') for r in ais if r.get('model')), ''),
				},
				'config': config, 'has_parent': False, 'chunk': None, 'done': True, 'progress': 100,
				'last_updated_db': end,
				'context': {k: v for k, v in first['_context'].items() if k not in ('tool_call_id', 'tool_call_name')},
			}
		return list(orphans)

	def _read_destination(self):
		"""Map source docs to the copies a previous run of this migration wrote."""
		self.existing_findings, self.existing_runners, self.existing_notes = {}, {}, set()
		self.notes_listed = True
		if not self.dst_ws:
			return
		engine = self.dst_engine = self._engine(self.dst, self.dst_ws, self.new_name)
		for rec in engine.search({}, scope_only=True, include_internal=True):
			src = (rec.get('_context') or {}).get('migrated_from')
			if src in self.findings:
				self.existing_findings[src] = rec
				self._seed_ids(self.findings[src].get('_context') or {}, rec['_context'])
		for doc in engine.list_runners(workspace_id=self.dst_ws):
			src = (doc.get('context') or {}).get('migrated_from')
			if src in self.runners:
				self.existing_runners[src] = doc
				self._seed_ids(self.runners[src]['context'], doc['context'])
		notes = engine.list_notes()
		self.notes_listed = notes is not None
		self.existing_notes = {(n.get('_context') or {}).get('migrated_from') for n in notes or []}

	def _seed_ids(self, src_ctx, dst_ctx):
		for k in ID_KEYS:
			if src_ctx.get(k) and dst_ctx.get(k):
				self.ids.setdefault(src_ctx[k], dst_ctx[k])

	# ---------- relink ----------

	def _context(self, ctx):
		"""A source context relinked to the destination workspace and ids."""
		# 'api' marks a doc the api driver already stored: the destination driver sets its own.
		ctx = {k: v for k, v in ctx.items() if k != 'api'}
		ctx.update(workspace_id=self.dst_ws, workspace_name=self.new_name, drivers=[hooks_driver(self.dst)])
		for k in ID_KEYS:
			if ctx.get(k):
				ctx[k] = self.ids.setdefault(ctx[k], str(uuid.uuid4()))
		return ctx

	# ---------- write ----------

	def _run_hooks(self, run, event, *args):
		"""Run the destination driver's hooks for ``event``; a failing write is reported and
		skipped so one bad doc does not stop the migration (as Runner.run_hooks does)."""
		result = args[0] if args else None
		hooks = self._driver_hooks.get(RUNNER_CLASSES[run.config.type], {}).get(event, [])
		try:
			for hook in hooks:
				result = hook(run, *args) or result
		except Exception as e:
			self.failed += 1
			src = (getattr(result, '_context', None) or run.context).get('migrated_from')
			console.print(Warning(message=f'{self.dst} {event} hook failed for {src}: {e}'))
			return None
		return result if args else True

	def _runner_doc(self, doc):
		doc = {k: v for k, v in doc.items() if not k.startswith('_')}  # listing-only keys (_id, _path...)
		for k in ('start_time', 'end_time'):
			doc[k] = to_datetime(doc.get(k))
		if not doc.get('done') and not self.keep_status:
			# Nothing runs a migrated runner: one left unfinished in the source never ends.
			doc.update(status='FAILURE', done=True)
			doc['end_time'] = doc['end_time'] or to_datetime(doc.get('last_updated_db')) or doc['start_time']
		return doc

	def _write_runners(self):
		def order(item):  # parents first, so their ids are known when a child is written
			doc = item[1]
			return (bool(doc.get('has_parent')), list(RUNNER_CLASSES).index(doc['config']['type']),
					bool(doc['context'].get('task_chunk_id')), str(doc.get('start_time') or ''))

		for key, src in sorted(self.runners.items(), key=order):
			doc = self._runner_doc(src)
			doc['context'] = {**self._context(src['context']), 'migrated_from': key}
			rtype = doc['config']['type']
			parent = None
			if doc.get('has_parent'):
				pkeys = ('workflow_id', 'scan_id') if rtype == 'task' else ('scan_id',)
				parent = next((self.runs[src['context'][k]] for k in pkeys if src['context'].get(k) in self.runs), None)
			existing = self.existing_runners.get(key) or {}
			folder = Path(existing['_path']).parent if existing.get('_path') else None
			run = self.runs[key] = StoredRunner(doc, self.new_name, parent=parent, reports_folder=folder)
			before = dict(run.context)
			self._run_hooks(run, 'on_end')
			for k in ID_KEYS:  # the ids the driver replaced on write (mongodb ObjectIds, api remote ids)
				if src['context'].get(k) and run.context.get(k) != before.get(k):
					self.ids[src['context'][k]] = run.context[k]
		for key, run in self.runs.items():
			src_ctx = self.runners[key]['context']
			relinked = {k: self.ids[src_ctx[k]] for k in ID_KEYS if src_ctx.get(k)}
			if any(run.context.get(k) != v for k, v in relinked.items()):
				run.context.update(relinked)
				self._run_hooks(run, 'on_end')

	def _owner(self, src_ctx):
		"""The migrated runner a finding was stored under (its closest one), if any."""
		return next((self.runs[src_ctx[k]] for k in ('task_chunk_id', 'task_id', 'workflow_id', 'scan_id')
					if src_ctx.get(k) in self.runs), None)

	def _write_findings(self):
		# Duplicates first, so the main copy's `_related` (its duplicates) maps to written ids.
		forward = []
		for src_uuid, rec in sorted(self.findings.items(), key=lambda i: not i[1].get('_duplicate')):
			src_ctx = rec.get('_context') or {}
			run = self._owner(src_ctx)
			item = next(load_output_types([rec]), None)
			if not run or not item:
				self.failed += 1
				console.print(Warning(message=f'Skipping finding {src_uuid} ({rec.get("_type")}): no migrated runner or type.'))  # noqa: E501
				continue
			existing = self.existing_findings.get(src_uuid)
			ctx = self._context(src_ctx)
			if existing:  # keep the destination's own markers on the copy (e.g. the api driver's)
				ctx = {**existing['_context'], **ctx}
			item._context = {**ctx, 'migrated_from': src_uuid}
			item._uuid = existing['_uuid'] if existing else str(uuid.uuid4())  # as Runner.add_result mints it
			item._related = [self.uuids.get(u, u) for u in rec.get('_related') or []]
			item = self._run_hooks(run, 'on_item', item)
			if not item:
				continue
			self.uuids[src_uuid] = item._uuid
			if any(u in self.findings and u not in self.uuids for u in rec.get('_related') or []):
				forward.append((rec, item, run))
		for rec, item, run in forward:
			item._related = [self.uuids.get(u, u) for u in rec.get('_related') or []]
			self._run_hooks(run, 'on_item', item)

	def _write_notes(self):
		for note in self.notes or []:
			src_id = note_id(note)
			if src_id in self.existing_notes:
				continue
			note = {k: v for k, v in note.items() if k not in ('_id', '_uuid')}
			for k in ('created_at', 'edited_at'):
				if note.get(k):
					note[k] = to_datetime(note[k])
			# a runner note keys on the runner id
			note['target_key'] = {k: self.ids.get(v, v) for k, v in (note.get('target_key') or {}).items()}
			note['_context'] = {**(note.get('_context') or {}), 'workspace_id': self.dst_ws, 'migrated_from': src_id}
			if not self.dst_engine.create_note(note):
				self.failed += 1

	def apply(self):
		"""Write the workspace to the destination, then tag its new duplicates as the driver does
		after a run. Findings keep their source dedup state."""
		if self.existing_findings or self.existing_runners:
			lost = [kind for kind, missing in (
				('runners', self.runners and not self.existing_runners),
				('notes', self.notes and not self.notes_listed)) if missing]
			if lost:
				raise RuntimeError(
					f'This migration already ran, but the {self.dst} driver does not return the {" and ".join(lost)} '
					'it wrote (context.migrated_from): re-running it would duplicate them, so it is refused.')
		if not self.dst_ws:
			self.dst_ws = resolve_workspace_id(self.dst, self.new_name, create=True)
			self.dst_engine = self._engine(self.dst, self.dst_ws, self.new_name)
		driver = hooks_driver(self.dst)
		self._driver_hooks = import_dynamic(f'secator.hooks.{driver}', 'HOOKS') or {}
		self._write_runners()
		self._write_findings()
		self._write_notes()
		for run in self.runs.values():
			if not run.has_parent:
				self._run_hooks(run, 'on_run_end')
		tag_duplicates = import_dynamic(f'secator.hooks.{driver}', 'tag_duplicates')
		if tag_duplicates:
			# every migrated finding in one pass (unbounded): one never tagged at the source is untagged
			tag_duplicates(self.dst_ws, max_items=-1)

	# ---------- report ----------

	def plan(self):
		"""Rows (kind, source count, new, existing) of what ``apply`` writes."""
		rows = []
		runner_types = Counter(r['config']['type'] for r in self.runners.values())
		existing = Counter(self.runners[k]['config']['type'] for k in self.existing_runners)
		for t in RUNNER_CLASSES:
			rows.append((f'{t}s', runner_types[t], runner_types[t] - existing[t], existing[t]))
		finding_types = Counter(r.get('_type') for r in self.findings.values())
		existing = Counter(self.findings[k].get('_type') for k in self.existing_findings)
		for t, n in sorted(finding_types.items()):
			rows.append((f'findings: {t}', n, n - existing[t], existing[t]))
		if self.notes is not None:
			old = sum(1 for n in self.notes if note_id(n) in self.existing_notes)
			rows.append(('notes', len(self.notes), len(self.notes) - old, old))
		return rows

	def destination_counts(self):
		"""Counts of the migrated copies read back from the destination, keyed like ``plan`` rows."""
		engine = self._engine(self.dst, self.dst_ws, self.new_name)
		runners = engine.list_runners(workspace_id=self.dst_ws)
		marked = [r for r in runners if (r.get('context') or {}).get('migrated_from') in self.runners]
		# a driver that keeps no runner marker (api): count the workspace's runners
		counts = Counter(f'{r["config"]["type"]}s' for r in marked or runners if r.get('config'))
		counts.update(
			f'findings: {r.get("_type")}' for r in engine.search({}, scope_only=True, include_internal=True)
			if r['_context'].get('migrated_from') in self.findings)
		notes = engine.list_notes()
		if notes is not None:
			src_ids = {note_id(n) for n in self.notes or []}
			counts['notes'] = sum(1 for n in notes if (n.get('_context') or {}).get('migrated_from') in src_ids)
		return counts
