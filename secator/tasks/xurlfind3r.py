import validators
from collections import defaultdict
from urllib.parse import urlparse, urlunparse, parse_qs

from secator.runners import Command
from secator.definitions import HOST, OPT_NOT_SUPPORTED, URL
from secator.output_types import Url
from secator.decorators import task
from secator.serializers import JSONSerializer

MAX_PARAM_OCCURRENCES = 10


@task()
class xurlfind3r(Command):
    """Discover URLs for a given domain in a simple, passive and efficient way"""
    cmd = 'xurlfind3r'
    tags = ['url', 'recon']
    input_types = [HOST, URL]
    output_types = [Url]
    item_loaders = [JSONSerializer()]
    json_flag = '--jsonl'
    file_flag = '-l'
    input_flag = '-d'
    version_flag = OPT_NOT_SUPPORTED
    opts = {
        'sources': {'type': str, 'help': 'Sources to use (comma-delimited)', 'required': False},
        'sources_to_exclude': {'type': str, 'help': 'Sources to exclude (comma-delimited)', 'required': False},
        'include_subdomains': {'is_flag': True, 'help': 'Include subdomains', 'required': False, 'default': False},
        'max_param_occurrences': {'type': int, 'help': 'Max occurrences for the same parameter in the same URL before discarding next results', 'required': False, 'default': 10, 'internal': True},  # noqa: E501
    }
    install_version = '1.3.0'
    install_cmd = 'go install -v github.com/hueristiq/xurlfind3r/cmd/xurlfind3r@[install_version]'
    install_github_handle = 'hueristiq/xurlfind3r'
    proxychains = False
    proxy_socks5 = True
    proxy_http = True
    profile = 'io'

    @staticmethod
    def before_init(self):
        for idx, input in enumerate(self.inputs):
            if validators.url(input):
                self.inputs[idx] = urlparse(input).netloc

    @staticmethod
    def on_init(self):
        self.max_param_occurrences = self.get_opt_value('max_param_occurrences')
        self.seen_params = defaultdict(lambda: defaultdict(int))

    @staticmethod
    def on_json_loaded(self, item):
        url = item['url']
        parsed_url = urlparse(url)
        base_url = urlunparse(parsed_url._replace(query="", fragment=""))  # Remove query & fragment
        query_params = parse_qs(parsed_url.query)
        current_params = set(query_params.keys())
        for param in current_params:
            self.seen_params[base_url][param] += 1
            if self.seen_params[base_url][param] > int(self.max_param_occurrences):
                return
        yield Url(url=item['url'], extra_data={'source': item['source']})
