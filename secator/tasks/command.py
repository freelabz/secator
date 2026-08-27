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

		# Seed the caller-supplied start_time BEFORE mark_started() fires on_start, so the
		# hook persists the imported time rather than the auto-stamped now().
		runner.mark_started(start_time=start_time or datetime.fromtimestamp(time(), timezone.utc))

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

		# Seed the caller-supplied end_time BEFORE mark_completed() fires on_end (the
		# persistence path), so the hook saves the imported time rather than now().
		runner.mark_completed(end_time=end_time or datetime.fromtimestamp(time(), timezone.utc))

		return runner
