from secator.config import CONFIG
from secator.definitions import HASH
from secator.decorators import task
from secator.runners import Command


@task()
class haiti(Command):
    """Hash identifier"""
    cmd = 'haiti'
    input_types = [HASH]
    output_types = [HASH]
    install_github_handle = 'noraj/haiti'
    install_cmd = f'gem install haiti-hash --user-install -n {CONFIG.dirs.bin}'
