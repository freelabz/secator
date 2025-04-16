from secator.decorators import task
from secator.definitions import (DOMAIN, HOST, RATE_LIMIT, RETRIES, THREADS, WORDLIST, EXTRA_DATA)
from secator.config import CONFIG
from secator.output_types import Subdomain
from secator.serializers import JSONSerializer
from secator.tasks._categories import ReconMixin
from secator.utils import process_wordlist
from secator.runners import Command


@task()
class dnsxbrute(Command, ReconMixin):
    """dnsx is a fast and multi-purpose DNS toolkit designed for running various library."""
    cmd = 'dnsx'
    json_flag = '-json'
    input_flag = '-domain'
    input_type = HOST
    file_flag = '-domain'
    output_types = [Subdomain]
    opt_key_map = {
        RATE_LIMIT: 'rate-limit',
        RETRIES: 'retry',
        THREADS: 'threads',
    }
    opts = {
        WORDLIST: {'type': str, 'short': 'w', 'default': CONFIG.wordlists.defaults.dns, 'process': process_wordlist, 'help': 'Wordlist to use'},  # noqa: E501
        'trace': {'is_flag': True, 'default': False, 'help': 'Perform dns tracing'},
    }
    item_loaders = [JSONSerializer()]
    output_map = {
        Subdomain: {
            HOST: 'host',
            DOMAIN: lambda x: ".".join(x['host'].split('.')[1:]),
            EXTRA_DATA: lambda x: {
                'resolver': x['resolver'],
                'status_code': x['status_code']
			}
        }
    }
    install_cmd = 'go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest'
    install_github_handle = 'projectdiscovery/dnsx'
    profile = 'io'
