import os
import yaml
import re

from secator.decorators import task 
from secator.runners import Command
from secator.output_types import Vulnerability, Error, Info
from secator.definitions import (OUTPUT_PATH)

@task()
class tfsec(Command):
    cmd = 'tfsec'

    json_flag = '-f json'

    output_types = [Vulnerability]

    ignore_return_code = True
    install_cmd = 'go install github.com/aquasecurity/tfsec/cmd/tfsec@v1.28.10'
    install_github_handle = 'aquasecurity/tfsec'

    @staticmethod
    def on_init(self):
        self.output_path = self.get_opt_value(OUTPUT_PATH)
        if not self.output_path:
            self.output_path = f'{self.reports_folder}/.outputs/{self.unique_name}.json'
        self.cmd += f' -O {self.output_path}'

    @staticmethod
    def on_cmd_done(self):
        if not os.path.exists(self.output_path):
            yield Error(message=f'Could not find JSON results in {self.output_path}')
            return

        yield Info(message=f'JSON results saved to {self.output_path}')
        with open(self.output_path, 'r') as f:
            results = yaml.safe_load(re.sub(r'\s', '', f.read()))
        if results['results']:
            # Custom rules
            for currentResult in results['results']:
                if not currentResult['rule_id']:
                    currentResult['rule_id'] = currentResult['long_id']

                yield Vulnerability(
                    name=currentResult['rule_id'],
                    severity=currentResult['severity'].lower(),
                    description=currentResult['rule_description'],
                    extra_data=currentResult['location'],
                    references=currentResult['links'],
                )
                pass
        else:
            yield Error(message=f'Results parsing error')