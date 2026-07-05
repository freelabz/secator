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
	# NOTE: input_types MUST be empty. A non-empty input_types makes the base
	# _validate_inputs() (secator/runners/_base.py) run autodetect_type() on each input and
	# DROP any whose detected type isn't in the list. A command line like "whoami" is
	# autodetected as 'slug' (not 'str'), so [STRING] would silently strip most bare
	# single-word commands -> empty inputs -> empty cmd -> FAILURE. An empty input_types
	# short-circuits the type filter entirely, which is correct: a command line is not a
	# typed scan target.
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
		"""Arbitrary shell commands have no fixed binary to `which`/auto-install (the base
		Command.is_installed() derives cmd_name from the class-level `cmd`, which is '' here).
		Always report installed so the base yielder runs the input verbatim instead of trying
		(and failing) to auto-install an empty command name.
		"""
		return True

	@classmethod
	def from_result(cls, command_line, output, return_code, *, start_time=None, end_time=None, context=None, hooks=None):
		"""Build a `command` runner from an ALREADY-RUN command's result, without executing it.

		This is the "import" path (as opposed to the "execute" path exercised by
		`run()`/`yielder()`): it never spawns a subprocess, it just populates the runner's
		state fields from a result that was captured elsewhere, then fires the same
		`on_start`/`on_end` hooks a normal run would fire so the imported command persists
		like any other runner (e.g. via an `update_runner` hook passed in `hooks`). This is
		the forward-looking seam for importing externally-run commands into Secator Cloud.

		Args:
			command_line (str): The command line that was run, verbatim. It becomes `self.cmd`
				via the constructor -> `_build_cmd()`, same as the live-execution path (with
				`input_types = []`, inputs are never type-filtered, so this holds for every
				command line, including bare single-word ones like "whoami").
			output (str): Captured stdout of the already-run command.
			return_code (int): Process return code of the already-run command. 0 means
				success; anything else marks the runner FAILURE (an `Error` result is added
				so `self_errors`, which `status` derives from, is non-empty).
			start_time (datetime, optional): When the command started (tz-aware). Defaults
				to now if omitted.
			end_time (datetime, optional): When the command finished (tz-aware). Defaults to
				now if omitted.
			context (dict, optional): Runner context (workspace, etc), same as the live path.
			hooks (dict, optional): Runner hooks (e.g. `on_end: [update_runner]`), same as the
				live path -- this is how the imported result gets persisted.

		Returns:
			command: the populated runner, in SUCCESS or FAILURE status. `yielder()` /
			`run()` are never called, so no subprocess is ever spawned.
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
			# `status` derives FAILURE from `self_errors` being non-empty (see
			# secator/runners/_base.py). add_result() stamps `_source` to this runner's
			# unique_name, which is what `_owns_error()` matches on for a task runner.
			# output=False is REQUIRED: the default (output=True) would do
			# `self.output += repr(item)` (_base.py), appending this synthetic Error's
			# ANSI-colored repr onto the caller's captured stdout and corrupting it.
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
