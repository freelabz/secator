from secator.decorators import task
from secator.runners import Command
from secator.definitions import OPT_PIPE_INPUT, OPT_NOT_SUPPORTED, URL
from secator.output_types import Url

@task()
class qsreplace(Command):
    cmd = 'qsreplace'
    file_flag = OPT_PIPE_INPUT
    input_flag = OPT_PIPE_INPUT
    opts = {
        'a': {'type': str, 'help': 'pattern to replace url'}
    }
    input_type = URL
    install_cmd = (
        'go install github.com/tomnomnom/qsreplace@latest'
    )
    output_types = [Url]

    @staticmethod
    def item_loader(self, line):
        yield {'url': line}
