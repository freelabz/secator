"""Store-driven live poll — reads a run's live findings from the secator store (``QueryEngine``)
instead of the Celery result backend, and renders the same progress panel.

Since #1312 findings and runner docs both live in the store, so a run can be tracked with zero
Celery reads: stream new findings via ``iterate`` each cycle, and read each task's live
state/progress from its runner doc (``list_runners``), matched to the build-time task topology
(``celery_ids_map``) by celery id. Stop when the root runner doc is terminal (or on revoke /
inactivity). See docs/superpowers/specs/2026-08-19-store-driven-live-polling-design.md.
"""
import time as _time
from contextlib import nullcontext

from secator.config import CONFIG
from secator.definitions import STATE_COLORS
from secator.rich import console
from secator.utils import debug

try:
	from greenlet import GreenletExit
except ImportError:  # greenlet not installed (no eventlet/gevent worker pool)
	class GreenletExit(BaseException):
		pass

TERMINAL_STATES = {'SUCCESS', 'FAILURE', 'REVOKED'}

# Client-side poll inactivity bound: if the root doc never finalizes and nothing advances within
# this window, stop rather than hang (a worker died before writing the terminal status; the
# server-side watchdog revokes it independently). Aligns with the server RUNNER_INACTIVITY_HOURS.
# ponytail: promote to a config key (runners.poll_inactivity_seconds) if it needs tuning.
DEFAULT_INACTIVITY_SECONDS = 2 * 3600


class StorePoller:
	"""Poll a run's findings + progress from the store. Drop-in for the old CeleryData poll."""

	def __init__(self, engine, findings_query, root_id, root_type,
				 ids_map=None, main_id=None, revoked=False,
				 report_dir=None, refresh_interval=None,
				 inactivity_seconds=DEFAULT_INACTIVITY_SECONDS,
				 print_remote_info=True, print_remote_title='Results',
				 rehydrate=None, sleep_func=None, time_func=None):
		"""
		Args:
			engine: a ``QueryEngine`` (or any object exposing ``list_runners`` + ``iterate``).
			findings_query (dict): run-scoped findings query, e.g. ``{'_context.scan_id': id}``.
			root_id (str): the run's root runner id (the top-most {type}_id).
			root_type (str): 'scan' | 'workflow' | 'task'.
			ids_map (dict): the runner's ``celery_ids_map`` — the build-time task topology (rows,
				names, descriptions), keyed by celery task id. The panel is drawn from this so the
				full task tree (incl. not-yet-started tasks) shows, with descriptions, and workflow
				nodes are excluded (see ``main_id``) — matching the old Celery panel.
			main_id (str): the root's own celery id; its row is hidden when real subtasks exist.
			revoked (bool): the run is being torn down (Ctrl+C) — flush once and exit, don't wait
				for a terminal status.
			report_dir (str): local hint so the json backend reads only this run's report tree.
			refresh_interval (float): seconds between polls (default CONFIG.runners.poll_frequency).
			inactivity_seconds (float|None): stop if nothing advances within this window (None = off).
			sleep_func / time_func: injectable for tests.
		"""
		self.engine = engine
		self.findings_query = findings_query or {}
		self.root_id = str(root_id)
		self.root_type = root_type
		self.ids_map = ids_map or {}
		self.main_id = main_id
		self.revoked = revoked
		self.report_dir = report_dir
		self.refresh_interval = CONFIG.runners.poll_frequency if refresh_interval is None else refresh_interval
		self.inactivity_seconds = inactivity_seconds
		self.print_remote_info = print_remote_info
		self.print_remote_title = print_remote_title
		self._sleep = sleep_func or _time.sleep
		self._time = time_func or _time.monotonic
		# Rehydrate store dicts -> OutputType objects, exactly like the results StreamView, so the
		# runner's _process_item receives the same objects it does on the Celery path.
		if rehydrate is None:
			from secator.output_types._base import load_output_types
			rehydrate = load_output_types
		self._rehydrate = rehydrate
		self._seen = set()          # yielded finding uuids (dedup contract, like CeleryData)
		self._scanned = 0           # total findings read from the store (efficiency counter)
		self._watermark = 0         # max _timestamp fetched so far — incremental fetch floor
		self._last_status = None
		self._exclude_main = any(tid != self.main_id for tid in self.ids_map)
		self._panel_cache = {}

	# --- store reads -----------------------------------------------------------------------------
	def _runners_in_scope(self):
		"""Runner docs belonging to this run (root + descendants), scoped by the root {type}_id."""
		runners = self.engine.list_runners(report_dir=self.report_dir)
		key = f'{self.root_type}_id'
		return [r for r in runners if str((r.get('context') or {}).get(key)) == self.root_id]

	def _root_status(self, runners):
		"""Status of the run's root doc (the in-scope runner with no parent)."""
		roots = [r for r in runners if not r.get('has_parent')]
		if roots:
			return roots[0].get('status')
		return runners[0].get('status') if runners else None

	def _state_by_celery_id(self, runners):
		"""Map each task's live {state, progress, count} by its celery id (docs carry it in
		context.celery_id — set by the worker), so it matches celery_ids_map's keys."""
		out = {}
		for r in runners:
			cid = (r.get('context') or {}).get('celery_id')
			if cid:
				out[str(cid)] = r
		return out

	def _iter_new_findings(self):
		"""Yield findings not yielded before (dedup by _uuid), streamed one batch at a time.

		Incremental: only fetch findings at/after the highest ``_timestamp`` seen so far, so each
		cycle costs O(new findings) rather than re-scanning the whole set (indexed on DB backends).
		``$gte`` re-reads the boundary second; the ``_uuid`` dedup drops those re-reads."""
		query = dict(self.findings_query)
		if self._watermark:
			query['_timestamp'] = {'$gte': self._watermark}
		high = self._watermark
		for batch in self.engine.iterate(query):
			self._scanned += len(batch)
			for item in self._rehydrate(batch):
				uuid = item.get('_uuid') if isinstance(item, dict) else getattr(item, '_uuid', None)
				ts = item.get('_timestamp') if isinstance(item, dict) else getattr(item, '_timestamp', None)
				if ts and ts > high:
					high = ts
				if uuid and uuid in self._seen:
					continue
				if uuid:
					self._seen.add(uuid)
				yield item
		self._watermark = high

	# --- main loop -------------------------------------------------------------------------------
	def iter_results(self):
		"""Generator: yield findings as they land; render the live panel; stop when the root doc is
		terminal, the run is revoked, or the inactivity window elapses."""
		progress = self._init_panel() if self.print_remote_info else nullcontext()
		with progress:
			try:
				yield from self._poll_loop(progress)
			except (KeyboardInterrupt, GreenletExit):
				# Ctrl+C / greenlet kill: flush remaining findings, then re-raise so the runner's
				# error handler revokes the remote tasks (mirrors the old Celery poll's contract).
				try:
					yield from self._iter_new_findings()
				except Exception:
					pass
				raise

	def _poll_loop(self, progress):
		last_advance = self._time()
		while True:
			try:
				runners = self._runners_in_scope()
			except Exception as e:
				debug(f'store poll list_runners failed: {e}', sub='store.poll')  # transient; retry
				runners = []
			status = self._root_status(runners)
			advanced = False
			scanned = self._scanned
			try:
				for item in self._iter_new_findings():
					advanced = True
					yield item
			except Exception as e:
				debug(f'store poll iterate failed: {e}', sub='store.poll')
			if status != self._last_status:
				advanced = True
				self._last_status = status
			if self.print_remote_info:
				self._render(progress, runners)
			debug(f'cycle: scanned {self._scanned - scanned}, status={status}, revoked={self.revoked}',
				  sub='store.poll')
			if advanced:
				last_advance = self._time()

			# Exit conditions: revoked teardown (flush once, don't wait), terminal root, timeout.
			if self.revoked:
				break
			if status in TERMINAL_STATES:
				break
			if self.inactivity_seconds is not None and (self._time() - last_advance) > self.inactivity_seconds:
				debug(f'store poll inactivity timeout after {self.inactivity_seconds}s', sub='store.poll')
				break
			self._sleep(self.refresh_interval)

	# --- rendering -------------------------------------------------------------------------------
	def _init_panel(self):
		"""Build the progress panel and seed one row per task from celery_ids_map (excluding the
		root/main node) — so the full tree, with descriptions, shows from the start."""
		from rich.progress import Progress as RichProgress, SpinnerColumn, TextColumn, TimeElapsedColumn
		from rich.panel import Panel
		from rich.padding import Padding
		title = self.print_remote_title

		class PanelProgress(RichProgress):
			def get_renderables(self):
				yield Padding(Panel(self.make_tasks_table(self.tasks), title=title,
									border_style='bold gold3', expand=False, highlight=True), pad=(2, 0, 0, 0))

		progress = PanelProgress(
			SpinnerColumn('dots'),
			TextColumn('{task.fields[descr]}  '),
			TextColumn('[bold cyan]{task.fields[full_name]}[/]'),
			TextColumn('{task.fields[state]:<20}'),
			TimeElapsedColumn(),
			TextColumn('{task.fields[count]}'),
			TextColumn('{task.fields[progress]}%'),
			auto_refresh=False, transient=False, console=console,
		)
		for tid, data in self.ids_map.items():
			if self._exclude_main and tid == self.main_id:
				continue
			if data.get('chunk') and self._exclude_main:
				continue  # hide chunk rows in a workflow/scan panel (parent row shows aggregate)
			self._panel_cache[tid] = progress.add_task('', **self._row_fields(data))
		return progress

	def _row_fields(self, data, state=None, progress=None, count=None):
		st = state if state is not None else data.get('state', 'PENDING')
		descr = data.get('descr', '') or ''
		if len(descr) > 50:
			descr = descr[:50] + '...'
		return dict(
			descr=descr,
			full_name=data.get('full_name', data.get('name', '')),
			state=f'[{STATE_COLORS.get(st, "white")}]{st}[/]',
			count=count if count is not None else data.get('count', 0) or 0,
			progress=progress if progress is not None else data.get('progress', 0) or 0,
		)

	def _render(self, progress, runners):
		"""Update each task row's state/progress from its store doc (matched by celery id)."""
		by_cid = self._state_by_celery_id(runners)
		for tid, pid in self._panel_cache.items():
			doc = by_cid.get(str(tid))
			data = self.ids_map.get(tid, {})
			if doc:
				st = doc.get('status', data.get('state', 'PENDING'))
				if self.revoked and st in ('PENDING', 'RUNNING'):
					st = 'REVOKED'
				progress.update(pid, **self._row_fields(data, state=st, progress=doc.get('progress', 0) or 0,
														count=doc.get('count', 0) or 0))
			elif self.revoked:
				progress.update(pid, **self._row_fields(data, state='REVOKED'))
		progress.refresh()
