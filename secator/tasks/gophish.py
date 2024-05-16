from secator.decorators import task
from secator.runners import Command


@task()
class gophish(Command):
	cmd = 'gophish'
	install_github_handle = 'gophish/gophish'
	install_github_bin_only = False