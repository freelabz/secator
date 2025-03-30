from secator.decorators import task
from secator.runners import Command


@task()
class haiti(Command):
    cmd = 'haiti'

    install_cmd = 'gem install haiti-hash'
    install_github_handle = 'noraj/haiti'
