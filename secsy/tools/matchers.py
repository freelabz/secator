from secsy.cmd import CommandRunner
from secsy.definitions import *


class gf(CommandRunner):
    """Wrapper around grep, to help you grep for things."""
    cmd = 'gf'
    file_flag = OPT_PIPE_INPUT
    input_flag = OPT_PIPE_INPUT
    opts = {
        'pattern': {'type': str, 'required': True, 'help': 'Pattern names to match against (comma-delimited)'}
    }
    opt_key_map = {
        'pattern': ''
    }
    input_type = URL
    install_cmd = 'go install -v github.com/tomnomnom/gf@latest'
    output_type = 'tags'
    output_schema = ['match']
    item_loader = lambda self, line: {'match': line}