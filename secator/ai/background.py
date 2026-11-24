"""Background jobs for the ``ai`` task.

A ``run_task`` / ``run_workflow`` / ``run_shell`` call made with ``background: true`` is
not awaited by the agent loop: it is approved by the guardrails exactly like a
foreground call, then dispatched through the SAME handler (``safe_dispatch_action``) in
a daemon thread of the ``ai`` task process. The turn continues with the foreground
calls only; the model reads a background job's results later with
``check_background_jobs`` and stops one with ``cancel_background_job``.

Design notes (kept deliberately small):

* **One process, no cross-process state.** A job lives as long as the ``ai`` task that
started it: at the end of the run (stop, error, max iterations, revoke) every running
job is cancelled and its final status recorded (see ``ai._teardown_background``).
Nothing has to be recovered by a later ``ai`` task, so the job registry can stay in
memory while the durable record goes through the normal driver path.
* **Durable record through drivers only.** The child runners persist their own docs and
findings via the driver hooks rebuilt for every child (``_child_preamble``), and the
``ai`` task records each job transition as an ``Ai(ai_type="background_job")`` item
through ``add_result``. Both work identically on every driver (json, sqlite, mongodb,
api); nothing here reads or writes a driver directly.
* **Main-thread persistence.** The job thread only buffers the items it produces. The
``ai`` task drains them from its own thread (``drain``) and runs ``add_result`` /
yields them there, so hooks and the output stream are never touched concurrently.
* **Cancellation.** In-process child runners register themselves on their job through
an ``on_init`` hook (:func:`register_runner_hook`), keyed by the job thread. Cancel
sends SIGTERM to their processes and revokes their Celery tasks when they run
asynchronously.
"""
import itertools
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

# Action types (``action`` key of a tool call) that may run in the background.
BACKGROUND_ACTIONS = ("task", "workflow", "shell", "subagent")

# Action types that run in the background unless the call says ``background: false``.
# A subagent is a full agent loop (minutes to hours) whose result is one compact
# handback, so the parent keeps working by default; see run_subagent's schema.
BACKGROUND_BY_DEFAULT = ("subagent",)

# Job statuses. ``running`` is the only non-final one.
RUNNING = "running"
DONE = "done"
FAILED = "failed"
CANCELLED = "cancelled"

# Execution-only items a job buffers but never surfaces (same set the agent loop skips).
_SKIPPED_TYPES = ("stat", "progress", "state", "info")

# Thread ident -> BackgroundJob, for runners constructed inside a job thread.
_THREAD_JOBS: Dict[int, "BackgroundJob"] = {}


class BackgroundLimitError(Exception):
	"""Raised when submitting a job would exceed the concurrent background job limit."""


def current_job() -> Optional["BackgroundJob"]:
	"""Return the background job running in the current thread, if any."""
	return _THREAD_JOBS.get(threading.get_ident())


def register_runner_hook(runner):
	"""``on_init`` hook: attach a runner built in a job thread to that job.

	Module-level so it pickles by reference when the hooks travel to a Celery worker;
	there it finds no job for its thread and does nothing.
	"""
	job = current_job()
	if job is not None:
		job.add_runner(runner)


def add_background_hooks(hooks: Dict) -> Dict:
	"""Return a copy of a class-keyed child hooks dict with :func:`register_runner_hook`.

	Lists are copied so the driver modules' shared ``HOOKS`` dicts are never mutated.
	"""
	from secator.runners import Task, Workflow
	out = dict(hooks or {})
	for cls in (Task, Workflow):
		per_cls = dict(out.get(cls, {}))
		per_cls["on_init"] = list(per_cls.get("on_init", [])) + [register_runner_hook]
		out[cls] = per_cls
	return out


def _item_type(item) -> str:
	if isinstance(item, dict):
		return item.get("_type", "")
	return getattr(item, "_type", "") or ""


@dataclass
class BackgroundJob:
	"""One background tool call and the items it produced so far."""
	id: str
	action: Dict
	description: str = ""
	status: str = RUNNING
	started: float = field(default_factory=time.time)
	ended: Optional[float] = None
	error: str = ""
	items: List[Any] = field(default_factory=list)
	runners: List[Any] = field(default_factory=list)
	# Cursors into ``items``: drained by the ai task (persist + stream) / reported to the model.
	drained: int = 0
	reported: int = 0
	# Last status recorded as an Ai item by the ai task (to record each transition once).
	recorded_status: str = ""
	# Store-backed tracking. ``detached``: the child was dispatched fire-and-forget to Celery
	# (no thread waits on it); its completion and results then come from the store only.
	can_detach: bool = False
	detached: bool = False
	store_status: Optional[Dict] = None
	store_seen: set = field(default_factory=set, repr=False)
	last_refresh: float = 0.0
	# Set once the model polled the job after it finished (its final status was seen).
	final_read: bool = False
	cancel_event: threading.Event = field(default_factory=threading.Event, repr=False)
	thread: Optional[threading.Thread] = field(default=None, repr=False)
	_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

	@property
	def tool(self) -> str:
		return self.action.get("tool_call_name") or self.action.get("action", "")

	@property
	def finished(self) -> bool:
		return self.status != RUNNING

	@property
	def elapsed(self) -> float:
		return (self.ended or time.time()) - self.started

	def add_runner(self, runner):
		with self._lock:
			self.runners.append(runner)
		if self.cancel_event.is_set():
			_stop_runner(runner)

	def append(self, item):
		with self._lock:
			self.items.append(item)

	def take_undrained(self) -> List[Any]:
		with self._lock:
			new = self.items[self.drained:]
			self.drained = len(self.items)
		return new

	def take_unreported(self) -> List[Any]:
		with self._lock:
			new = self.items[self.reported:]
			self.reported = len(self.items)
		return [i for i in new if _item_type(i) not in _SKIPPED_TYPES]

	def store_ref(self):
		"""``(runner_type, [candidate ids])`` of the job's top-level child runner, or None.

		The ids are minted before dispatch (``_child_preamble``); the candidates cover the keys
		the drivers may have keyed the runner doc on (``{type}_chunk_id`` / ``{type}_id``)."""
		with self._lock:
			runner = self.runners[0] if self.runners else None
		if runner is None:
			return None
		rtype = getattr(getattr(runner, "config", None), "type", "") or "task"
		ctx = getattr(runner, "context", None) or {}
		ids = [ctx.get(f"{rtype}_chunk_id"), ctx.get(f"{rtype}_id")]
		return rtype, [i for i in dict.fromkeys(ids) if i]

	def label(self) -> str:
		name = self.action.get("name") or self.action.get("command") or self.tool
		return f"{self.tool}({name})" if name != self.tool else self.tool

	def summary(self) -> str:
		pending = len([i for i in self.items[self.reported:] if _item_type(i) not in _SKIPPED_TYPES])
		line = f"{self.id} [{self.status}, {int(self.elapsed)}s] {self.label()}"
		if self.description:
			line += f" - {self.description}"
		if pending:
			line += f" ({pending} unread result(s))"
		if self.store_status and not self.finished:
			line += f" [{self.store_status.get('status', '').lower()} {self.store_status.get('progress', 0)}%]"
		if self.error:
			line += f" error: {self.error}"
		return line

	def to_dict(self) -> Dict:
		return {
			"job_id": self.id,
			"status": self.status,
			"tool": self.tool,
			"description": self.description,
			"elapsed": round(self.elapsed, 1),
			"items": len(self.items),
			"error": self.error,
			"runner_ids": self.runner_ids(),
			"runners": self.runner_refs(),
			"detached": self.detached,
			"runner_status": (self.store_status or {}).get("status", ""),
		}

	def runner_refs(self, limit: int = 10) -> List[Dict]:
		"""The runners this job spawned so far, each as ``{id, type, name, query}``.

		Known from the moment a runner is built (its ``on_init`` hook registers it, before it
		runs), so a running job's partial findings can already be read with
		``query_workspace(query=<query>)``. ``id`` is the key of the
		runner doc (its ``{type}_chunk_id`` for an AI-spawned task, else its ``{type}_id``);
		``query`` scopes findings by ``_context.{type}_id``, the key every finding of that runner
		carries. Runners seen only through a runner card (none registered) are listed by id."""
		refs, seen = [], set()
		with self._lock:
			runners = list(self.runners)
		for r in runners:
			rtype = getattr(getattr(r, "config", None), "type", "") or "task"
			ctx = getattr(r, "context", None) or {}
			if not isinstance(ctx, dict):
				continue
			scope_id = ctx.get(f"{rtype}_id")
			rid = ctx.get(f"{rtype}_chunk_id") or scope_id
			if not rid or rid in seen:
				continue
			seen.add(rid)
			ref = {"id": rid, "type": rtype, "name": getattr(getattr(r, "config", None), "name", "") or ""}
			if scope_id:
				ref["query"] = {f"_context.{rtype}_id": scope_id}
			refs.append(ref)
		for rid, rtype, name in self._card_refs():
			if rid not in seen:
				seen.add(rid)
				refs.append({"id": rid, "type": rtype, "name": name})
		return refs[:limit]

	def _card_refs(self) -> List[tuple]:
		"""``(runner_id, runner_type, name)`` of the runner cards among the job items."""
		out = []
		with self._lock:
			items = list(self.items)
		for i in items:
			if _item_type(i) != "ai":
				continue
			extra = (i.get("extra_data") if isinstance(i, dict) else getattr(i, "extra_data", None)) or {}
			rid = extra.get("runner_id")
			if rid:
				content = i.get("content") if isinstance(i, dict) else getattr(i, "content", "")
				out.append((rid, extra.get("runner_type") or "task", (content or "")[:80]))
		return out

	def runner_ids(self) -> List[str]:
		"""Ids of the runners this job spawned (from their runner cards), for later lookup."""
		ids = []
		for rid, _, _ in self._card_refs():
			if rid not in ids:
				ids.append(rid)
		return ids


def wants_background(action: Dict) -> bool:
	"""Whether a validated tool-call action should run as a background job."""
	act = action.get("action", "")
	if act not in BACKGROUND_ACTIONS:
		return False
	flag = action.get("background")
	if flag is None:
		return act in BACKGROUND_BY_DEFAULT
	if isinstance(flag, str):
		return flag.strip().lower() in ("1", "true", "yes")
	return bool(flag)


def _stop_runner(runner):
	"""Best-effort stop of one child runner.

	Kills its process (Command), revokes its Celery tasks (async runner) and sets
	``stop_requested`` so a cooperative runner (an ``ai`` subagent loop) ends at its
	next iteration and tears down its own background jobs.
	"""
	import signal
	try:
		runner.stop_requested = True
	except Exception:  # noqa: BLE001 - cancellation is best-effort
		pass
	try:
		if getattr(runner, "celery_ids_map", None) and not getattr(runner, "sync", True):
			runner.stop_celery_tasks()
	except Exception:  # noqa: BLE001 - cancellation is best-effort
		pass
	try:
		if callable(getattr(runner, "stop_process", None)):
			runner.stop_process(exit_ok=True, sig=signal.SIGTERM)
	except Exception:  # noqa: BLE001 - cancellation is best-effort
		pass


class BackgroundJobs:
	"""Registry of the background jobs started by one ``ai`` task.

	Args:
		max_jobs: Max number of RUNNING jobs at once; a submit beyond it is refused.
		max_wait: Upper bound (seconds) of any single wait on background jobs.
	"""

	# Store runner statuses that end a job, and the job status they map to.
	_TERMINAL = {"SUCCESS": DONE, "SKIPPED": DONE, "FAILURE": FAILED, "REVOKED": CANCELLED}
	# Min seconds between two store status reads for one job.
	REFRESH_EVERY = 2.0

	def __init__(self, max_jobs: int = 3, max_wait: int = 600, store: Any = None):
		self.max_jobs = max(int(max_jobs or 0), 0)
		self.max_wait = max(int(max_wait or 0), 0)
		# Query engine over the run's drivers (``get_runner_status`` + ``search``), or None when
		# the run persists nothing. With a store, a job's status and findings are read from it
		# by runner id, so a job on another worker is polled exactly like an in-process one.
		self.store = store
		self.jobs: Dict[str, BackgroundJob] = {}
		self._ids = itertools.count(1)
		self._cond = threading.Condition()
		self._hold_since: Optional[float] = None

	def should_hold_idle(self) -> bool:
		"""Whether an idle input timer should stay frozen: jobs are running, and the hold
		started less than ``max_wait`` seconds ago. Resets once no job is running."""
		if not self.running():
			self._hold_since = None
			return False
		if self._hold_since is None:
			self._hold_since = time.time()
		return (time.time() - self._hold_since) < self.max_wait

	# -- queries -----------------------------------------------------------

	def get(self, job_id: str) -> Optional[BackgroundJob]:
		return self.jobs.get(job_id)

	def running(self) -> List[BackgroundJob]:
		self.refresh()
		return [j for j in self.jobs.values() if not j.finished]

	def refresh(self, jobs: Optional[List[BackgroundJob]] = None, force: bool = False):
		"""Update running jobs from the store (throttled). A detached job finishes only here."""
		if self.store is None:
			return
		now = time.time()
		for job in (jobs if jobs is not None else list(self.jobs.values())):
			if job.finished or (not force and now - job.last_refresh < self.REFRESH_EVERY):
				continue
			job.last_refresh = now
			ref = job.store_ref()
			if not ref:
				continue
			rtype, ids = ref
			for rid in ids:
				try:
					st = self.store.get_runner_status(rid, rtype)
				except Exception:  # noqa: BLE001 - a store hiccup must not break the loop
					st = None
				if st:
					job.store_status = st
					break
			final = self._TERMINAL.get((job.store_status or {}).get("status", ""))
			thread_done = job.thread is None or not job.thread.is_alive()
			# An in-process job ends with its thread (it also drains its last items); a
			# detached job (thread already gone) ends when the store says its runner did.
			if final and job.detached and thread_done:
				with self._cond:
					if job.status == RUNNING:
						job.status = final
						job.ended = time.time()
					self._cond.notify_all()

	def store_results(self, job: BackgroundJob) -> List[Dict]:
		"""Findings of a job's child runner read from the store, not yet reported (by ``_uuid``)."""
		if self.store is None:
			return []
		ref = job.store_ref()
		if not ref:
			return []
		rtype, ids = ref
		key = f"_context.{rtype}_chunk_id" if rtype == "task" else f"_context.{rtype}_id"
		try:
			found = self.store.search({key: ids[0]}, limit=500) or []
		except Exception:  # noqa: BLE001 - a store hiccup must not break polling
			return []
		out = []
		for r in found:
			uid = r.get("_uuid") if isinstance(r, dict) else None
			if uid and uid in job.store_seen:
				continue
			if uid:
				job.store_seen.add(uid)
			out.append(r)
		return out

	def unread(self) -> List[BackgroundJob]:
		"""Jobs still running, or finished with results the model has not read yet."""
		return [j for j in self.jobs.values()
		        if not j.finished or j.reported < len(j.items) or not j.final_read]

	def status_block(self) -> str:
		"""Short per-turn status of the jobs the model still has to care about ("" if none)."""
		self.refresh()
		jobs = self.unread()
		if not jobs:
			return ""
		lines = [j.summary() for j in jobs]
		finished = [j.id for j in jobs if j.finished]
		note = ""
		if finished:
			note = (f"FINISHED since you last read them: {', '.join(finished)}. Read them with "
			        f"check_background_jobs NOW, then tell the user in your message what each one found, "
			        f"with your analysis (e.g. 'Subagent <name> finished and exploited <X>: <analysis>'). "
			        f"Never let a finished job pass silently.\n")
		return (
			"<background_jobs>\n" + "\n".join(lines) + "\n" + note +
			"Read results with check_background_jobs (pass wait=<seconds> to block until a job "
			"finishes); stop one you no longer need with cancel_background_job.\n"
			"</background_jobs>")

	# -- lifecycle ---------------------------------------------------------

	def submit(self, action: Dict, ctx: Any, dispatch: Callable) -> BackgroundJob:
		"""Start ``dispatch(action, ctx)`` in a daemon thread and return its job.

		``ctx`` is copied with ``silent=True`` (no console interleaving with the
		foreground) and must be the context the call was approved with: the job runs
		the exact same handler as a foreground call.

		Raises:
			BackgroundLimitError: when ``max_jobs`` jobs are already running.
		"""
		from dataclasses import replace
		if len(self.running()) >= self.max_jobs:
			raise BackgroundLimitError(
				f"Too many background jobs running ({len(self.running())}/{self.max_jobs}). Wait for one with "
				f"check_background_jobs(wait=...), cancel one with cancel_background_job, or run this call "
				f"in the foreground (background=false).")
		job = BackgroundJob(
			id=f"bg-{next(self._ids)}",
			action=dict(action),
			description=action.get("description", ""),
			can_detach=self.store is not None)
		self.jobs[job.id] = job
		job_ctx = replace(ctx, silent=True, in_batch=False)

		def _run():
			_THREAD_JOBS[threading.get_ident()] = job
			try:
				for item in dispatch(job.action, job_ctx):
					job.append(item)
					if job.cancel_event.is_set():
						# Runners registered after the cancel (e.g. a workflow's next task)
						# are stopped on registration; re-stop the known ones in case a
						# process started after the first signal.
						for r in list(job.runners):
							_stop_runner(r)
			except Exception as e:  # noqa: BLE001 - dispatch is already exception-safe; belt and braces
				job.error = f"{type(e).__name__}: {e}"
			finally:
				_THREAD_JOBS.pop(threading.get_ident(), None)
				with self._cond:
					job.ended = time.time()
					has_error = bool(job.error) or any(_item_type(i) == "error" for i in job.items)
					# A detached job's thread only dispatched it: unless the dispatch itself
					# failed, it keeps running until the store reports its runner's end.
					if job.status == RUNNING and (has_error or not job.detached):
						job.status = FAILED if has_error else DONE
					self._cond.notify_all()

		job.thread = threading.Thread(target=_run, name=f"secator-ai-{job.id}", daemon=True)
		job.thread.start()
		return job

	def cancel(self, job_id: str) -> Optional[BackgroundJob]:
		"""Cancel a running job (best-effort stop of its runners). Returns the job or None."""
		job = self.jobs.get(job_id)
		if job is None or job.finished:
			return job
		job.cancel_event.set()
		with self._cond:
			job.status = CANCELLED
			job.ended = time.time()
			self._cond.notify_all()
		with job._lock:
			runners = list(job.runners)
		for r in runners:
			_stop_runner(r)
		return job

	def cancel_all(self, join_timeout: float = 10.0) -> List[BackgroundJob]:
		"""Cancel every running job and give their threads ``join_timeout`` seconds to unwind."""
		cancelled = [self.cancel(j.id) for j in self.running()]
		deadline = time.time() + join_timeout
		for job in cancelled:
			if job and job.thread is not None:
				job.thread.join(timeout=max(deadline - time.time(), 0))
		return [j for j in cancelled if j]

	def wait(self, job_ids: List[str], timeout: float = 0) -> bool:
		"""Block until one of ``job_ids`` is finished, bounded by ``min(timeout, max_wait)``.

		Returns True if a watched job is finished (or none of them exists), False on timeout.
		"""
		timeout = min(max(float(timeout or 0), 0), self.max_wait)
		deadline = time.time() + timeout
		step = 1.0
		while True:
			watched = [self.jobs[i] for i in job_ids if i in self.jobs]
			self.refresh(watched)
			if not watched or any(j.finished for j in watched):
				return True
			remaining = deadline - time.time()
			if remaining <= 0:
				return False
			# Wake on an in-process job's end (notify), else poll the store with backoff.
			with self._cond:
				self._cond.wait(timeout=min(remaining, step))
			step = min(step * 2, 15.0)

	def wait_any(self, timeout: float) -> bool:
		"""Block until any CURRENTLY running job finishes (bounded by ``max_wait``)."""
		ids = [j.id for j in self.running()]
		if not ids:
			return True
		return self.wait(ids, timeout=timeout)

	def poll(self, job_ids: Optional[List[str]] = None, wait: float = 0):
		"""Return ``[(job, new_items)]`` for the requested jobs (default: all).

		``new_items`` are the job's items produced since the previous poll (partial
		results while running, the rest once finished). With ``wait`` > 0, first block
		until one of the requested running jobs finishes (bounded by ``max_wait``).
		"""
		ids = [i for i in (job_ids or []) if i]
		if wait:
			running_ids = [i for i in (ids or self.jobs) if i in self.jobs and not self.jobs[i].finished]
			if running_ids:
				self.wait(running_ids, timeout=wait)
		jobs = [self.jobs[i] for i in ids if i in self.jobs] if ids else list(self.jobs.values())
		self.refresh(jobs, force=True)
		out = []
		for job in jobs:
			items = job.take_unreported()
			for i in items:  # the job's own copy wins; the store adds what the job never saw
				uid = i.get("_uuid") if isinstance(i, dict) else getattr(i, "_uuid", None)
				if uid:
					job.store_seen.add(uid)
			out.append((job, items + self.store_results(job)))
			if job.finished:
				job.final_read = True
		return out
