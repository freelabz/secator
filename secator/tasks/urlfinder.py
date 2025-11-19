from secator.runners import Command
from secator.definitions import HOST, OPT_NOT_SUPPORTED
from secator.output_types import Url
from secator.decorators import task
from secator.serializers import JSONSerializer


@task()
class urlfinder(Command):
    """Find URLs in text."""
    cmd = 'urlfinder'
    input_types = [HOST]  # anything
    output_types = [Url]
    item_loaders = [JSONSerializer()]
    json_flag = '-j'
    tags = ['pattern', 'scan']
    file_flag = '-list'
    input_flag = '-d'
    version_flag = OPT_NOT_SUPPORTED
    opts = {
        'sources': {'type': str, 'help': 'Sources to use (comma-delimited)', 'required': False},
        'exclude_sources': {'type': str, 'help': 'Sources to exclude (comma-delimited)', 'required': False},
        'url_scope': {'type': str, 'help': 'URL scope (comma-delimited)', 'required': False},
        'url_out_scope': {'type': str, 'help': 'URL out scope (comma-delimited)', 'required': False},
        'field_scope': {'type': str, 'help': 'Field scope (comma-delimited)', 'required': False},
        'no_scope': {'type': bool, 'help': 'No scope', 'required': False},
        'display_out_scope': {'type': bool, 'help': 'Display out scope', 'required': False},
        'match': {'type': str, 'help': 'Match (comma-delimited)', 'required': False},
        'filter': {'type': str, 'help': 'Filter (comma-delimited)', 'required': False},
        'rate_limit': {'type': int, 'help': 'Rate limit', 'required': False},
        'rate_limits': {'type': str, 'help': 'Rate limits (comma-delimited)', 'required': False},
        'update': {'type': bool, 'help': 'Update', 'required': False},
        'disable_update_check': {'type': bool, 'help': 'Disable update check', 'required': False},
        'output': {'type': str, 'help': 'Output file', 'required': False},
        'jsonl': {'type': bool, 'help': 'JSONL output format', 'required': False},
        'output_dir': {'type': str, 'help': 'Output directory', 'required': False},
        'collect_sources': {'type': bool, 'help': 'Collect sources', 'required': False},
        'config': {'type': str, 'help': 'Config file', 'required': False},
        'provider_config': {'type': str, 'help': 'Provider config file', 'required': False},
        'proxy': {'type': str, 'help': 'HTTP proxy', 'required': False},
        'silent': {'type': bool, 'help': 'Silent', 'required': False},
        'version': {'type': bool, 'help': 'Version', 'required': False},
        'v': {'type': bool, 'help': 'Verbose output', 'required': False},
        'nc': {'type': bool, 'help': 'No color', 'required': False},
        'list_sources': {'type': bool, 'help': 'List sources', 'required': False},
        'stats': {'type': bool, 'help': 'Display source statistics', 'required': False},
        'timeout': {'type': int, 'help': 'Timeout in seconds', 'required': False},
        'max_time': {'type': int, 'help': 'Max time in minutes for enumeration', 'required': False},
    }
    opt_key_map = {
        'sources': 's',
        'exclude_sources': 'es',
        'url_scope': 'us',
        'url_out_scope': 'uos',
        'field_scope': 'fs',
        'no_scope': 'ns',
        'display_out_scope': 'do',
        'match': 'm',
        'filter': 'f',
    }
    encoding = 'ansi'
    install_version = 'v0.0.3'
    install_cmd = 'go install -v github.com/projectdiscovery/urlfinder/cmd/urlfinder@[install_version]'
    install_github_handle = 'projectdiscovery/urlfinder'
    proxychains = False
    proxy_socks5 = True
    proxy_http = True
    profile = 'io'

    @staticmethod
    def on_json_loaded(self, item):
        yield Url(url=item['url'], extra_data={'source': item['source']})
