"""Store-driven live poll — reads a run's live topology/state/progress + findings from the
secator store (``QueryEngine``) instead of the Celery result backend.

The runner docs (task/workflow/scan status + progress) and findings both live in the store since
#1312, so a run can be tracked with zero Celery reads: query ``list_runners`` for the tree and
``iterate`` for new findings each cycle, and stop when the root runner doc reaches a terminal
status. See docs/superpowers/specs/2026-08-19-store-driven-live-polling-design.md.
"""
import time as _time
from contextlib import nullcontext

from secator.config import CONFIG
from secator.rich import console
from secator.utils import debug

TERMINAL_STATES = {'SUCCESS', 'FAILURE', 'REVOKED'}

# Client-side poll inactivity bound: if the root doc never finalizes and nothing advances within
# this window, stop rather than hang (a worker died before writing the terminal status; the
# server-side watchdog revokes it independently). Aligns with the server RUNNER_INACTIVITY_HOURS.
# ponytail: promote to a config key (runners.poll_inactivity_seconds) if it needs tuning.
DEFAULT_INACTIVITY_SECONDS = 2 * 3600


class StorePoller:
	"""Poll a run's findings + progress from the store. Drop-in for CeleryData.iter_results."""

	def __init__(self, engine, findings_query, root_id, root_type,
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
			report_dir (str): local hint so the json backend reads only this run's report tree.
			refresh_interval (float): seconds between polls (default CONFIG.runners.poll_frequency).
			inactivity_seconds (float|None): stop if nothing advances within this window (None = off).
			sleep_func / time_func: injectable for tests.
		"""
		self.engine = engine
		self.findings_query = findings_query or {}
		self.root_id = str(root_id)
		self.root_type = root_type
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

	def _runners_in_scope(self):
		"""All runner docs belonging to this run (the root + its descendants).

		Scoped by the root {type}_id in each doc's context — backend-agnostic (json is already
		narrowed by report_dir; DB backends return the workspace set and we filter here)."""
		runners = self.engine.list_runners(report_dir=self.report_dir)
		key = f'{self.root_type}_id'
		out = []
		for r in runners:
			ctx = r.get('context') or {}
			if str(ctx.get(key)) == self.root_id:
				out.append(r)
		return out

	def _root_status(self, runners):
		"""Status of the run's root doc (the in-scope runner with no parent)."""
		roots = [r for r in runners if not r.get('has_parent')]
		if roots:
			return roots[0].get('status')
		return runners[0].get('status') if runners else None

	def _iter_new_findings(self):
		"""Yield findings not yielded before (dedup by _uuid), streamed one batch at a time.

		Incremental: only fetch findings at/after the highest ``_timestamp`` seen so far, so each
		cycle costs O(new findings) rather than re-scanning the whole set (indexed on DB backends;
		on json the file is still read but only new items are rehydrated/deduped). ``$gte`` (not
		``$gt``) re-reads the boundary second; the ``_uuid`` dedup drops those re-reads."""
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

	def iter_results(self):
		"""Generator: yield findings as they land; render the live panel from runner docs; stop when
		the root doc is terminal or the inactivity window elapses."""
		progress = self._make_panel() if self.print_remote_info else nullcontext()
		last_advance = self._time()
		with progress:
			while True:
				try:
					runners = self._runners_in_scope()
				except Exception as e:
					# Transient store error: log and retry next cycle (never aborts the run).
					debug(f'store poll list_runners failed: {e}', sub='store.poll')
					runners = []
				status = self._root_status(runners)
				advanced = False
				scanned = self._scanned
				yielded_before = len(self._seen)
				try:
					for item in self._iter_new_findings():
						advanced = True
						yield item
				except Exception as e:
					debug(f'store poll iterate failed: {e}', sub='store.poll')
				debug(
					f'cycle: {len(runners)} runners, scanned {self._scanned - scanned} findings, '
					f'yielded {len(self._seen) - yielded_before} new (status={status})',
					sub='store.poll')
				if status != self._last_status:
					advanced = True
					self._last_status = status
				if self.print_remote_info and runners:
					self._render(progress, runners)
				if advanced:
					last_advance = self._time()

				if status in TERMINAL_STATES:
					debug(f'root {self.root_type}:{self.root_id} terminal: {status}', sub='store.poll')
					break
				if self.inactivity_seconds is not None and (self._time() - last_advance) > self.inactivity_seconds:
					debug(f'store poll inactivity timeout after {self.inactivity_seconds}s', sub='store.poll')
					break
				self._sleep(self.refresh_interval)

	# --- rendering (only when print_remote_info) -------------------------------------------------
	# NOTE: replicates a minimal panel rather than reaching into CeleryData's inline PanelProgress,
	# to avoid touching the hot Celery path. ponytail: dedupe the two panels once StorePoller is the
	# default and the Celery poll is removed.
	def _make_panel(self):
		from rich.progress import Progress as RichProgress, SpinnerColumn, TextColumn, TimeElapsedColumn
		from rich.panel import Panel
		from rich.padding import Padding
		title = self.print_remote_title

		class PanelProgress(RichProgress):
			def get_renderables(self):
				yield Padding(Panel(self.make_tasks_table(self.tasks), title=title,
									border_style='bold gold3', expand=False, highlight=True), pad=(2, 0, 0, 0))

		self._panel_cache = {}
		return PanelProgress(
			SpinnerColumn('dots'),
			TextColumn('[bold cyan]{task.fields[full_name]}[/]'),
			TextColumn('{task.fields[state]:<20}'),
			TimeElapsedColumn(),
			TextColumn('{task.fields[count]}'),
			TextColumn('{task.fields[progress]}%'),
			auto_refresh=False, transient=False, console=console,
		)

	def _render(self, progress, runners):
		from secator.celery_utils import STATE_COLORS
		for r in runners:
			rid = r.get('_id') or r.get('name')
			state = r.get('status', 'PENDING')
			color = STATE_COLORS.get(state, 'white')
			fields = dict(
				full_name=r.get('name', ''),
				state=f'[{color}]{state}[/]',
				count=r.get('count', 0) or 0,
				progress=r.get('progress', 0) or 0,
			)
			if rid not in self._panel_cache:
				self._panel_cache[rid] = progress.add_task('', **fields)
			else:
				progress.update(self._panel_cache[rid], **fields)
		progress.refresh()
