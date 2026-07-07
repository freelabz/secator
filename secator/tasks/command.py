from datetime import datetime, timezone
from time import time

from secator.decorators import task
from secator.output_types import Error
from secator.runners import Command


@task()
class command(Command):
	"""Run an arbitrary shell command verbatim."""
	cmd = ''
	shell = True
	input_flag = None
	# NOTE: input_types MUST stay empty. A non-empty list makes _validate_inputs()
	# autodetect each input's type and drop mismatches (e.g. "whoami" autodetects as
	# 'slug', not 'str', so [STRING] would strip most bare commands -> empty cmd -> FAILURE).
	input_types = []
	output_types = []

	def _build_cmd(self):
		"""Set the command to the raw input verbatim (no flag/opt append, no quoting)."""
		self.cmd = self.inputs[0] if self.inputs else ''
		self.cmd_options = {}
		# Command.__init__ runs _build_cmd_input() BEFORE _build_cmd(), and it clobbers
		# self.shell to (' | ' in self.cmd) — i.e. False for most commands. Restore the
		# intended shell mode so &&, ;, redirects, $VAR, globbing are interpreted.
		self.shell = True

	def is_installed(self):
		"""Always report installed: there's no fixed binary to `which` (cmd_name derives
		from the empty class-level `cmd`), so auto-install would wrongly fail."""
		return True

	@classmethod
	def from_result(cls, command_line, output, return_code, *, start_time=None, end_time=None, context=None, hooks=None):
		"""Build a `command` runner from an ALREADY-RUN result, without executing it: the
		"import" path (vs. `run()`/`yielder()`'s "execute" path). Populates state fields
		from a result captured elsewhere, then fires the same `on_start`/`on_end` hooks so
		it persists like any other runner -- the seam for importing externally-run commands
		into Secator Cloud. `return_code != 0` marks the runner FAILURE via a synthetic
		`Error` result; `start_time`/`end_time` default to now if omitted. Returns the
		populated runner (no subprocess is ever spawned).
		"""
		runner = cls(inputs=[command_line], context=context or {}, hooks=hooks or {})

		# mark_started() fires the on_start hook. It also stamps start_time = now(), so
		# apply the caller-supplied start_time right after (mark_started() unconditionally
		# overwrites it, there's no way to seed it beforehand).
		runner.mark_started()
		runner.start_time = start_time or datetime.fromtimestamp(time(), timezone.utc)

		# Populate the captured result.
		runner.output = output
		runner.return_code = return_code
		if return_code != 0:
			# `status` derives FAILURE from `self_errors` being non-empty; add_result() stamps
			# `_source` for `_owns_error()` matching. output=False is REQUIRED -- the default
			# would append this synthetic Error's ANSI repr onto the captured stdout, corrupting it.
			runner.add_result(
				Error(message=f'Command exited with return code {return_code}'),
				print=False,
				output=False,
			)

		# mark_completed() fires the on_end hook (the persistence path). Same caveat as
		# start_time: it unconditionally stamps end_time = now(), so apply the
		# caller-supplied end_time right after.
		runner.mark_completed()
		runner.end_time = end_time or datetime.fromtimestamp(time(), timezone.utc)

		return runner
