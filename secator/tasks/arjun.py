import yaml

from secator.decorators import task
from secator.runners import Command
from secator.definitions import (OUTPUT_PATH)
from secator.output_types import Info, Url

@task()
class arjun(Command):
    cmd = 'arjun'
    input_flag = '-u'
    opts = {
        'm':{'type': str, 'help': 'Method [GET/POST/JSON/XML]'},
        't':{'type': int, 'help': 'Multi-threading'},
        'd':{'type': int, 'help': 'Delay between requests'},
        'T':{'type': int, 'help': 'Request timeout'},
        'c':{'type': int, 'help': 'Control query/chunk size'},
        'stable': {'is_flag': True, 'default': False, 'help':'Handle rate limits'},
        'ratelimit':{'type': int, 'help': 'Specify rate limit'},
    }

    install_cmd = 'pipx install arjun'
    install_github_handle = 's0md3v/Arjun'

    @staticmethod
    def on_init(self):
        self.output_path = self.get_opt_value(OUTPUT_PATH)
        if not self.output_path:
            self.output_path = f'{self.reports_folder}/.outputs/{self.unique_name}.json'
        self.cmd += f' -oJ {self.output_path}'

    @staticmethod
    def on_cmd_done(self):
        yield Info(message=f'JSON results saved to {self.output_path}')
        with open(self.output_path, 'r') as f:
            results = yaml.safe_load(f.read())
        for url,values in results.items():
            yield Url(
                url=url + str(values['params']),
                headers=values['headers'],
                method=values['method'],
            )