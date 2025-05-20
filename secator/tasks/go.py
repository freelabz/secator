from secator.config import CONFIG
from secator.decorators import util
from secator.runners import Command


@util()
class go(Command):
    cmd = 'go'
    install_pre = {'*': ['wget', 'tar']}
    install_version = '1.24.0'
    install_cmd = (
        f'wget -N https://golang.org/dl/go[install_version].linux-amd64.tar.gz -O {CONFIG.dirs.share}/go[install_version].linux-amd64.tar.gz &&'  # noqa: E501
        f'tar -xvzf {CONFIG.dirs.share}/go[install_version].linux-amd64.tar.gz -C {CONFIG.dirs.share} &&'
        f'ln -sf {CONFIG.dirs.share}/go/bin/go {CONFIG.dirs.bin}/go'
    )
