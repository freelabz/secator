import os
import yaml

from secator.decorators import task 
from secator.runners import Command
from secator.definitions import (OUTPUT_PATH, HEADER, PROXY, URL)
from secator.output_types import Tag, Info, Error

@task()
class wafw00f(Command):
    cmd = 'wafw00f'

    input_type = URL
    json_flag = '-f json'
    encoding = 'ansi'

    opt_prefix = '-'
    opts = {
        'l': {'is_flag': True, 'default': False, 'help': 'List all WAFs that WAFW00F is able to detect'},
        't': {'type': str, 'help': 'Test for one specific WAF'},
        'a': {'is_flag': True, 'default': False, 'help': 'Find all WAFs which match the signatures, do not stop testing on the first one'},
        'r': {'is_flag': True, 'default': False, 'help': 'Do not follow redirections given by 3xx responses'}
    }

    opt_key_map = {
        HEADER: 'H',
        PROXY: 'p'
    }

    output_types = [Tag]

    install_cmd = 'pipx install git+https://github.com/EnableSecurity/wafw00f.git'
    install_github_handle = 'EnableSecurity/wafw00f'

    @staticmethod
    def on_init(self):
        self.output_path = self.get_opt_value(OUTPUT_PATH)
        if not self.output_path:
            self.output_path = f'{self.reports_folder}/.outputs/{self.unique_name}.json'
        self.cmd += f' -o {self.output_path} '

    @staticmethod
    def on_cmd_done(self):
        # Skip parsing if -l is set
        if '-l' in self.cmd:
            pass
        else:
            if not os.path.exists(self.output_path):
                yield Error(message=f'Could not find JSON results in {self.output_path}')
                return

            yield Info(message=f'JSON results saved to {self.output_path}')
            with open(self.output_path, 'r') as f:
                results = yaml.safe_load(f.read())
            if results[0]['detected']:
                yield Tag(
                    name=results[0]['firewall'],
                    match=results[0]['manufacturer'],
                    extra_data= {'trigger_url': results[0]['trigger_url']}
                )
                pass