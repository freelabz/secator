"""Interactivity backends for AI task user interaction.

All user prompting (permission requests and follow-up questions) flows through
backend.ask_user().  Callers never branch on interactive mode — the backend
handles the UX differences.
"""
import time

from time import sleep
from typing import Any, Dict, List, Optional

from secator.ai.tools import STOP_TOOL_SCHEMA, STOP_TOOL_SCHEMA_SIMPLE


# Sentinel answer meaning "dismiss this follow-up/stop prompt" — the user declined
# all offered choices ("none of these work for me") instead of picking one. It
# resolves the pending prompt cleanly and ends the turn (the worker goes idle); the
# next typed user message starts a fresh turn via the normal resume/respawn path.
# Applies to `stopped`/`follow_up` CHOICE prompts ONLY, never to `permission`
# prompts (those stay a mandatory allow/deny). In the TUI the key is ESC.
DISMISS_ANSWER = "__dismiss__"


class UserInputTimeout(Exception):
	"""Raised by the RemoteBackend when a prompt goes unanswered past the timeout.

	In remote mode a prompt is NOT auto-denied on timeout (that produced weird
	states — an action silently denied while the user was away). Instead this
	exception unwinds the AI loop so the worker exits cleanly (saving infra $).
	The prompt stays ``pending`` (still answerable) and the run stamps it
	``extra_data.run_ended`` on the way out (see ``RemoteBackend.park_raised_prompts``),
	so a reader can tell no worker is polling it. Answering it later respawns the
	`ai` task, which restores the conversation and applies the answer.
	"""


class InteractivityBackend:
	"""Base class for AI interactivity backends."""

	# Whether there is a user to pause for at end-of-turn. True for CLI/TUI/Remote
	# (stop pauses and waits/polls), False for AutoBackend (stop ends immediately).
	# Gates the interactive-vs-autonomous `stop` guidance in the system prompt.
	interactive = True

	def ask_user(self, question: str, choices: List[str], session_id: str,
				 prompt_type: str = "stopped", **context) -> Optional[Dict]:
		"""Ask the user a question.

		Args:
			question: The question to ask.
			choices: List of choice strings.
			session_id: Session ID for correlating request/response.
			prompt_type: "stopped" (end-of-turn pause) or "permission".
			**context: Backend-specific context (engine, history, etc.).

		Returns:
			dict with at least {"answer": str}, or None (exit/timeout/deny).
			For a stopped pause: may also include "extra_iters" and "switch_mode".
		"""
		raise NotImplementedError

	def park_raised_prompts(self, session_id: str) -> int:
		"""Mark the prompts this backend raised that are still unanswered as parked.

		Called when the run ends (for any reason). No-op for backends that do not
		persist prompts. Returns the number of prompts parked.
		"""
		return 0

	def resolve_parked_prompts(self, session_id: str, query_engine=None) -> int:
		"""Resolve prompts that earlier, ended runs left unanswered (on resume).

		No-op for backends that do not persist prompts. Returns the number resolved.
		"""
		return 0

	def get_excluded_tools(self) -> set:
		"""Return tool names to exclude from the LLM's available tools.

		None by default: `stop` is the single end-of-turn signal in EVERY mode, so
		it's available everywhere. What `stop` does next (pause/wait vs end) is decided
		entirely by this backend's ask_user, not by withholding the tool.
		"""
		return set()

	def get_extra_tools(self) -> list:
		"""Return additional tool schemas (not in TOOL_SCHEMAS) to inject.

		Interactive backends expose a `stop` that may carry `choices`/`multiple` so the
		end-of-turn pause can offer the user concrete next steps. AutoBackend overrides
		this with a choiceless `stop` (a definitive stop — no user to pick a next step)."""
		return [STOP_TOOL_SCHEMA]

	def poll_steers(self, session_id=None) -> list:
		"""Drain pending mid-flight steers. No channel by default (CLI/Auto)."""
		return []

	@property
	def owns_display(self) -> bool:
		"""True if this backend owns the terminal (e.g. a full-screen TUI), so the
		runner should suppress its own console printing."""
		return False

	def on_session(self, workspace_id, context, session_id) -> None:
		"""Called once the ai task has resolved its session. No-op by default; a
		display backend can use it to wire up session-scoped views."""
		return None

	def get_initial_prompt(self, inputs, **context):
		"""Acquire the first prompt when none was passed. Default: the local
		terminal full-screen prompt (CLI/Auto); None in a worker / non-interactive
		backend (remote), which leaves the prompt to be resolved elsewhere."""
		from secator.definitions import IN_WORKER
		if IN_WORKER:
			return None
		from secator.rich import FullScreenPrompt
		targets_str = ', '.join(inputs) if inputs else 'no target'
		return FullScreenPrompt(
			title=f"What do you want to do? ({targets_str})",
			placeholder="e.g. Scan for vulnerabilities on this target...",
		).show()


class CLIBackend(InteractivityBackend):
	"""Local terminal interactive backend."""

	def ask_user(self, question, choices, session_id, prompt_type="stopped", **context):
		if prompt_type == "permission":
			return self._handle_permission(**context)
		return self._handle_end_prompt(choices, **context)

	def _handle_permission(self, **context):
		"""Delegate permission prompts to the PermissionEngine's rich menus."""
		engine = context.get("engine")
		ptype = context.get("permission_type")
		value = context.get("value", "")
		if not engine:
			return None

		if ptype == "shell":
			decision = engine.prompt_shell(value, reason=context.get("reason", ""))
			return {"answer": decision}
		elif ptype == "target":
			decision = engine.prompt_target(value, command=context.get("command", ""))
			return {"answer": decision}
		elif ptype in ("read", "write"):
			decision = engine.prompt_path(value, access_type=ptype, command=context.get("command", ""))
			return {"answer": decision}
		return None

	def _handle_end_prompt(self, choices, **context):
		"""Delegate the end-of-turn pause to the rich interactive menu."""
		from secator.ai.utils import prompt_user
		history = context.get("history")
		if not history:
			return None
		return prompt_user(
			history,
			max_iterations=context.get("max_iterations", 10),
			choices=choices,
			mode=context.get("mode", "chat"),
			model=context.get("model"),
		)


class RemoteBackend(InteractivityBackend):
	"""Remote DB-polling interactive backend."""

	def __init__(self, timeout: int = 600, query_engine: Any = None, poll_interval: int = 5):
		self.timeout = timeout
		self.query_engine = query_engine
		self.poll_interval = poll_interval
		# prompt_uuid of every prompt this backend persisted, so the run can park
		# the ones still unanswered when it ends (park_raised_prompts).
		self._raised_prompt_uuids = set()
		# Optional ``() -> bool``: while it returns True the idle input timer is FROZEN (the
		# ai task sets it to "background jobs are still running, within their max wait"), so
		# an idle user does not end the run and lose that work. Answers and steers are still
		# polled every tick, so the user can always answer or redirect.
		self.hold_while = None

	def idle_tick(self, elapsed: float, step: float) -> float:
		"""Advance the idle timer by ``step`` unless ``hold_while`` freezes it."""
		hold = self.hold_while
		try:
			if hold is not None and hold():
				return elapsed
		except Exception:  # noqa: BLE001 - a broken hold must never wedge the wait
			pass
		return elapsed + step

	def get_initial_prompt(self, inputs, **context):
		# remote runs in a worker; the first prompt arrives via context/resume, never
		# an interactive full-screen prompt
		return None

	def build_pending_prompt(self, question, choices, session_id, prompt_type="stopped", **context):
		"""Build a pending Ai finding for the remote user to see and answer.

		The caller must yield this item so it gets stored in the workspace
		(via runner hooks) before calling ask_user(), which will poll for the answer.

		``prompt_uuid`` (from context) is stamped into ``extra_data`` so the poll
		can match THIS exact prompt, not a stale earlier answer.
		"""
		from secator.output_types import Ai
		multiple = bool(context.get("multiple", False))
		extra_data = {
			"permission_type": context.get("permission_type", ""),
			"value": context.get("value", ""),
			# Mirror the top-level fields so a `stopped` pause carries its choices the same
			# way the stop handler's own doc does (clients read either).
			"choices": list(choices or []),
			"multiple": multiple,
		}
		prompt_uuid = context.get("prompt_uuid")
		if prompt_uuid:
			extra_data["prompt_uuid"] = prompt_uuid
			self._raised_prompt_uuids.add(prompt_uuid)
		# A new prompt for this session supersedes any older still-pending one OF THE
		# SAME TYPE (e.g. a worker that died mid-poll re-issuing the same kind of
		# prompt). Expire them BEFORE this doc is persisted so only the current prompt
		# stays live. Scope to `prompt_type` only: a permission prompt must NOT expire a
		# still-pending `stopped` prompt (and vice versa) — the two can be outstanding at
		# once, and cross-expiring orphaned the other prompt so it stopped awaiting an answer.
		self._expire_stale_pending(session_id, ai_type=prompt_type)
		# The conversation id rides on `_context.session_id` (auto-stamped from the
		# runner context on persist) — the poll + restore + remote server all key on
		# that, so this pending doc needs no top-level session_id field.
		return Ai(
			content=question,
			ai_type=prompt_type,
			status="pending",
			choices=list(choices or []),
			multiple=multiple,
			extra_data=extra_data,
			_timestamp=time.time(),
		)

	def track_prompt(self, prompt_uuid):
		"""Record ``prompt_uuid`` as a prompt this run raised, so run end parks it.

		For a pending doc persisted outside ``build_pending_prompt`` (the `stop` tool
		persists its own).
		"""
		if prompt_uuid:
			self._raised_prompt_uuids.add(prompt_uuid)

	def ask_user(self, question, choices, session_id, prompt_type="stopped", **context):
		# Record the prompt as this run's own even when its pending doc was persisted
		# elsewhere (the `stop` tool persists its own doc), so run end can park it.
		self.track_prompt(context.get("prompt_uuid"))
		answer = self._poll_for_answer(session_id, prompt_type, prompt_uuid=context.get("prompt_uuid"))
		if answer is None:
			return None

		if prompt_type == "permission":
			engine = context.get("engine")
			if answer in ("allow", "allow_all"):
				# BOTH persist a session-scoped rule so the guardrail re-check (which
				# re-evaluates the whole action after each approval to peel the next
				# layer) actually passes — a rule-less "one-shot" allow left the target
				# still unknown, so the re-check looped and re-prompted the same
				# target/path until it gave up (only allow_all, which persisted, worked).
				# `allow` = this exact value; `allow_all` = broader (whole host / parent).
				if engine:
					ptype = context.get("permission_type")
					value = context.get("value", "")
					self._add_permission_rules(engine, ptype, value, all_scope=(answer == "allow_all"))
				return {"answer": "allow"}
			return {"answer": "deny"}

		# stopped pause: return the answer text
		return {"answer": answer}

	def poll_steers(self, session_id):
		"""Drain pending steer docs for ``session_id`` and mark them consumed.

		A "steer" is a mid-flight user message: it's written into the channel
		(``_type:"ai"``, ``ai_type:"steer"``, ``status:"pending"``) WHILE the agent
		is running, and the worker picks it up at the next loop checkpoint to
		redirect the next turn. This is distinct from a follow-up ``answer`` (which
		the worker is *blocked* waiting on) and from a hard Stop (which revokes the
		Celery task).

		Returns a list of steer content strings (oldest-first). Each returned doc is
		flipped to ``status:"consumed"`` so it's injected exactly once. Robust by
		design: any backend error returns ``[]`` so a steer can never crash the run.
		"""
		if self.query_engine is None:
			return []
		base = {
			"_type": "ai",
			"ai_type": "steer",
			# Correlate by the runner context's session_id, auto-stamped on every
			# persisted item (item._context = self.context) — see _poll_for_answer.
			"_context.session_id": session_id,
			"status": "pending",
		}
		try:
			results = self.query_engine.search(base, limit=50)
		except Exception as e:  # noqa: BLE001 - a steer must never crash the run
			from secator.query._base import QueryBackendError
			if isinstance(e, QueryBackendError):
				# Keep a fatal backend error (e.g. rejected credentials) visible instead of silently dropping steers.
				from secator.output_types import Warning
				from secator.rich import console
				console.print(Warning(message=f'Steer poll failed: {e.message}'))
			return []
		if not results:
			return []
		# Oldest-first so multiple queued steers are injected in send order. Only inject a
		# steer we can ALSO mark consumed — i.e. one that carries a `_uuid`. Consume scopes
		# to the fetched `_uuid`s (below), so returning content for a `_uuid`-less doc would
		# re-serve the same pending steer on every poll and replay it as the user's answer
		# each turn until the same-answer loop-breaker trips (the duplicated interjection).
		# A `_uuid`-less steer is dropped once here instead of replayed forever.
		results = sorted(results, key=lambda r: r.get("_timestamp", 0))
		contents = []
		uuids = []
		for doc in results:
			u = doc.get("_uuid")
			content = doc.get("content") or doc.get("answer") or ""
			if u and content:
				contents.append(content)
				uuids.append(u)
		# Consume EXACTLY the docs we fetched (by _uuid), not the broad pending filter: a steer
		# that arrives between the search and this update would otherwise be flipped to consumed
		# without ever being injected (lost). Scoping to the fetched uuids also makes every
		# backend consume the same set (MongoDB update_one vs JSON/SQLite update_many).
		try:
			if uuids:
				self.query_engine.update(
					{**base, "_uuid": {"$in": uuids}},
					{"$set": {"status": "consumed"}},
				)
		except Exception:  # noqa: BLE001 - consume failure must not crash the run
			pass
		return contents

	def _poll_for_answer(self, session_id, prompt_type, prompt_uuid=None):
		"""Poll the DB for the answer to THIS specific prompt until timeout.

		The query MUST be scoped to the exact prompt the worker is currently
		blocked on — identified by ``prompt_uuid`` (stamped into the pending doc's
		``extra_data.prompt_uuid`` before it was persisted). Matching only on
		``{session_id, status:"answered"}`` is a bug: a multi-turn conversation
		accumulates *previously* answered prompt docs, so an unscoped query
		returns a STALE answer immediately, the worker re-injects that old answer
		as a brand-new prompt, re-runs the whole turn, asks again, re-matches the
		same stale doc — an infinite respawn loop that re-runs scans and burns
		tokens. Scoping on ``prompt_uuid`` makes the poll resolve only THIS
		prompt's own answer (and time out only THIS prompt's doc).

		A steer (mid-flight user message) breaks the wait: if a pending steer
		arrives for this session while we're blocked on a prompt, we return its
		content as the "answer" so the loop redirects immediately instead of
		stalling until the prompt is explicitly answered (or times out). This
		keeps prompt semantics intact for the no-steer case.
		"""
		base = {
			"_type": "ai",
			"ai_type": prompt_type,
			# session_id is auto-stamped on every persisted item (item._context)
			"_context.session_id": session_id,
		}
		if prompt_uuid:
			base["extra_data.prompt_uuid"] = prompt_uuid

		answered_query = {**base, "status": "answered"}
		elapsed = 0
		while elapsed < self.timeout:
			answer = self._resolve_answer(answered_query)
			if answer is not None:
				return answer
			# A steer breaks the wait: treat the steer as the user's answer so the
			# blocked follow-up resolves and the next turn redirects.
			steers = self.poll_steers(session_id)
			if steers:
				return "\n".join(steers)
			sleep(self.poll_interval)
			elapsed = self.idle_tick(elapsed, self.poll_interval)
		# One final search before giving up: the user may have answered during
		# the last sleep (or between the last search and now). Without this the
		# answer is silently stranded.
		answer = self._resolve_answer(answered_query)
		if answer is not None:
			return answer
		# Timeout with no answer. Do NOT return None (which the guardrail would
		# treat as a deny) — that produced the "silently auto-denied while the user
		# was away" state. Raise instead, so the AI loop unwinds and the worker exits
		# cleanly (saving infra $). The prompt stays pending (answerable); the run
		# parks it on its way out (park_raised_prompts), and answering it respawns
		# the task, which restores the conversation and applies the answer.
		raise UserInputTimeout(f"No answer for {prompt_type} prompt after {self.timeout}s; worker exiting")

	def park_raised_prompts(self, session_id):
		"""Stamp the prompts this backend raised that are still pending as parked.

		A run that ends (answer timeout, success, failure, iteration cap) no longer
		polls for an answer. Its unanswered prompts keep ``status: "pending"`` so a
		client can still answer them while the task is stopped (answering respawns the
		task, which restores the conversation and applies the answer, see
		``restore_history_from_db``), and get ``extra_data.run_ended: True`` so a reader
		can tell "waiting for an answer, no run live" from "a run is polling".
		Scoped to this run's own prompt_uuids, so it never touches a prompt raised by
		another run of the same session. An answer that already landed is left alone
		(the match is on ``pending``). Best-effort: a backend error never fails the run.
		"""
		if self.query_engine is None or not self._raised_prompt_uuids:
			return 0
		parked = 0
		# One update per prompt: some drivers update a single matching doc per call,
		# so an `$in` over several prompt_uuids would park only one of them.
		for prompt_uuid in sorted(self._raised_prompt_uuids):
			try:
				self.query_engine.update(
					{
						"_type": "ai",
						"_context.session_id": session_id,
						"status": "pending",
						"extra_data.prompt_uuid": prompt_uuid,
					},
					{"$set": {"extra_data.run_ended": True}},
				)
			except Exception:  # noqa: BLE001 - parking prompts must never fail the run
				continue
			self._raised_prompt_uuids.discard(prompt_uuid)
			parked += 1
		return parked

	def resolve_parked_prompts(self, session_id, query_engine=None):
		"""Resolve the parked prompts a resumed session will not act on.

		Called by a respawned run BEFORE it restores the conversation. A parked prompt
		that was answered while the task was stopped is already ``answered``, so it is
		not matched here and restore threads its answer into the history. One still
		``pending`` was superseded by the new message that respawned the task: it is
		marked ``timed_out`` (the status ``_expire_stale_pending`` gives a superseded
		prompt) so it stops showing as waiting. Resolving before the restore read
		means an answer either lands first (and is restored) or finds the prompt no
		longer pending. Only parked prompts (``extra_data.run_ended``) are matched,
		never one a live run is polling. ``query_engine`` overrides the backend's own,
		which is only wired once the loop starts. Known limit: a driver that searches
		then writes has a small window where an answer landing in between is
		overwritten. Best-effort: a backend error never fails the run.
		"""
		engine = query_engine if query_engine is not None else self.query_engine
		if engine is None:
			return 0
		base = {
			"_type": "ai",
			"_context.session_id": session_id,
			"status": "pending",
			"extra_data.run_ended": True,
		}
		try:
			docs = engine.search(base) or []
		except Exception:  # noqa: BLE001 - must never fail the run
			return 0
		resolved = 0
		# One update per prompt (some drivers update a single matching doc per call).
		for prompt_uuid in sorted({(d.get("extra_data") or {}).get("prompt_uuid") for d in docs} - {None}):
			try:
				engine.update(
					{**base, "extra_data.prompt_uuid": prompt_uuid},
					{"$set": {"status": "timed_out"}},
				)
			except Exception:  # noqa: BLE001 - must never fail the run
				continue
			resolved += 1
		return resolved

	def _resolve_answer(self, answered_query):
		"""Return the newest answered doc's answer, or None if none answered.

		Resolving against the newest by ``_timestamp`` is a backstop against
		stale answers.
		"""
		results = self.query_engine.search(answered_query)
		if not results:
			return None
		newest = max(results, key=lambda r: r.get("_timestamp", 0))
		return newest.get("answer")

	def _expire_stale_pending(self, session_id, ai_type=None):
		"""Mark older still-pending prompt(s) for this session as timed_out.

		Called when a NEW prompt starts (before it is persisted), so it only
		affects prior prompts. Stops stale 'pending' docs from accumulating —
		a worker that dies mid-poll otherwise leaves clients 'thinking' forever
		and lets crud.answer_ai_prompt's "latest pending" collide.

		``ai_type`` scopes the expiry to a single prompt type (the type of the
		incoming prompt). A permission prompt must NOT expire a still-pending
		`stopped` prompt (and vice versa): both can be outstanding at the same time,
		and expiring across types orphaned the other prompt so it stopped awaiting its
		answer. When ``ai_type`` is None both prompt types are expired (legacy).
		FLAG: a DB-layer TTL index on pending Ai docs is the durable follow-up.
		"""
		if not self.query_engine:
			return
		# Only expire PROMPT-like docs (stopped / permission). A blanket match on every
		# pending AI doc would also time out mid-flight `steer` interjections before
		# poll_steers/_drain_steers can consume them.
		ai_types = (ai_type,) if ai_type else ("stopped", "permission")
		for ai_type in ai_types:
			self.query_engine.update(
				{
					"_type": "ai",
					"ai_type": ai_type,
					"_context.session_id": session_id,
					"status": "pending",
				},
				{"$set": {"status": "timed_out"}},
			)

	@staticmethod
	def _add_permission_rules(engine, ptype, value, all_scope=False):
		"""Add runtime allow rules after a remote permission approval.

		``all_scope`` False (the "allow" button) grants the exact value; True (the
		"allow all" button) grants a broader scope — the whole host for a target, the
		parent directory for a path — mirroring the CLI's narrow-vs-broad menu.
		"""
		from secator.ai.guardrails import _extract_cmd_names, build_target_choices
		if ptype == "shell":
			# A single "allow" approves only the EXACT command (recorded separately in
			# approved_shell_commands by the caller), so add no broad rule here; only
			# "allow all" grants the binary(ies) for the whole run.
			if not all_scope:
				return
			cmd_names = _extract_cmd_names(value)
			if cmd_names:
				engine.add_runtime_allow([f"shell({','.join(cmd_names)})"])
			else:
				first_word = value.split()[0] if value.split() else value
				engine.add_runtime_allow([f"shell({first_word})"])
		elif ptype == "target":
			# Reuse the CLI menu's rule sets: narrow-first, broad-last. "allow" takes
			# the exact-value choice; "allow all" the broadest (whole host).
			choices = [c for c in build_target_choices(value) if c.get("rules")]
			if choices:
				rules = (choices[-1] if all_scope else choices[0])["rules"]
			else:
				rules = [f"target({value})"]
			engine.add_runtime_allow(rules)
		elif ptype in ("read", "write"):
			if all_scope and "/" in value:
				# A top-level path (`/foo`) has parent '' -> grant `/*`, never `//*`
				# (which matches nothing, so the re-check re-prompted until it denied).
				parent = value.rsplit("/", 1)[0]
				rules = [f"{ptype}({parent}/*)"] + ([f"{ptype}({parent})"] if parent else [])
				engine.add_runtime_allow(rules)
			else:
				engine.add_runtime_allow([f"{ptype}({value})"])


class AutoBackend(InteractivityBackend):
	"""Non-interactive autonomous backend (subagents + autonomous remote workers)."""

	interactive = False

	def get_extra_tools(self) -> list:
		# A choiceless `stop`: a definitive stop with no user to offer next steps to.
		return [STOP_TOOL_SCHEMA_SIMPLE]

	def ask_user(self, question, choices, session_id, prompt_type="stopped", **context):
		# No user to hand control back to: `stop` (and a content-only reply) ends the run.
		return None


class TUIBackend(InteractivityBackend):
	"""Interactive backend bridged to an active Textual TUI (secator.rich.get_tui()).

	Steers and user prompts flow through the TUI's thread-safe hooks instead of the
	rich prompt_toolkit menus (which would collide with Textual's display)."""

	def poll_steers(self, session_id=None):
		from secator.rich import get_tui
		tui = get_tui()
		try:
			return tui.tui_poll_steers() if tui is not None else []
		except Exception:  # noqa: BLE001 - a steer must never crash the run
			return []

	def ask_user(self, question, choices, session_id, prompt_type="stopped", **context):
		from secator.rich import get_tui
		tui = get_tui()
		if tui is None:
			return None
		res = tui.tui_ask_user(
			question, choices or [], prompt_type, multiple=bool(context.get("multiple", False)),
			command=context.get("command") or context.get("value") or "",
			solo=bool(context.get("solo", False)))
		answer = (res or {}).get("answer")
		if answer is None:
			return None
		if prompt_type == "permission":
			# Mirror RemoteBackend: persist a session-scoped rule so the guardrail
			# re-check passes — a rule-less one-shot "allow" leaves the value unknown,
			# so the engine re-prompts the SAME target/path in a loop (the bug).
			if answer in ("allow", "allow_all"):
				engine = context.get("engine")
				if engine:
					RemoteBackend._add_permission_rules(
						engine, context.get("permission_type"), context.get("value", ""),
						all_scope=(answer == "allow_all"))
				return {"answer": "allow"}
			return {"answer": "deny"}
		return {"answer": answer}

	@property
	def owns_display(self) -> bool:
		return True

	def on_session(self, workspace_id, context, session_id) -> None:
		from secator.rich import get_tui
		tui = get_tui()
		if tui is not None and hasattr(tui, "set_findings_source"):
			tui.set_findings_source(workspace_id, context, session_id)

	def get_initial_prompt(self, inputs, **context):
		# a string (possibly "") — NOT None — so the caller treats an empty answer as
		# "interactive backend, nothing given -> exit" rather than "non-interactive"
		res = self.ask_user(
			"What do you want to do?", [], context.get("session_id", ""), prompt_type="stopped")
		return (res or {}).get("answer") or ""


def create_backend(mode: str, timeout: int = 600, query_engine: Any = None, poll_interval: int = 5):
	"""Factory function to create the appropriate backend."""
	if mode == "local":
		return CLIBackend()
	elif mode == "remote":
		return RemoteBackend(timeout=timeout, query_engine=query_engine, poll_interval=poll_interval)
	elif mode == "tui":
		return TUIBackend()
	else:
		return AutoBackend()
