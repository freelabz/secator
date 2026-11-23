"""Child task run in-process by tests/unit/test_inprocess_children_pools.py (copied to the
templates folder so it is discovered as an external task)."""
from secator.decorators import task
from secator.output_types import Tag
from secator.runners import Command


@task()
class inproc_echo(Command):
	"""Echo each target back as a Tag."""
	cmd = 'echo'
	input_types = None
	output_types = [Tag]
	input_chunk_size = 1  # 2+ targets are chunked: exercises the eager chord / Task.replace path
	install_cmd = None

	@staticmethod
	def item_loader(self, line):
		line = line.strip()
		if line:
			yield Tag(category='info', name='echo', value=line, match=line)
