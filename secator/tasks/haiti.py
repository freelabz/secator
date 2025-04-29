from secator.config import CONFIG
from secator.decorators import task
from secator.runners import Command


@task()
class haiti(Command):
    cmd = 'haiti'
    install_cmd = f'gem install haiti-hash --user-install -n {CONFIG.dirs.bin}'
    install_github_handle = 'noraj/haiti'
