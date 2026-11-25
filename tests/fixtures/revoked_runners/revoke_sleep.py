"""Slow task of tests/unit/test_revoked_runners_worker.py, copied to the templates folder."""
from secator.decorators import task
from secator.output_types import Tag
from secator.runners import Command


@task()
class revoke_sleep(Command):
	"""Sleep for each target, a number of seconds."""
	cmd = 'sleep'
	input_types = None
	output_types = [Tag]
	input_chunk_size = 1  # 2+ targets are chunked
	install_cmd = None
	profile = 'revoke-test'

	def __init__(self, inputs=[], **run_opts):
		if run_opts.get('chunk') and 'boom' in inputs:
			raise RuntimeError('boom')  # the chunk fails in Celery (FAILURE), not in its command
		super().__init__(inputs, **run_opts)
