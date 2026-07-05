from secator.decorators import task
from secator.definitions import STRING
from secator.runners import Command


@task()
class command(Command):
	"""Run an arbitrary shell command verbatim."""
	cmd = ''
	shell = True
	input_flag = None
	input_types = [STRING]
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
