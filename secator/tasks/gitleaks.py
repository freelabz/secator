from secator.decorators import task
from secator.runners import Command
from secator.definitions import (OUTPUT_PATH)

import json


@task()
class gitleaks(Command):
    cmd = 'gitleaks dir'
    input_flag = None
    json_flag = '-f json'


    @staticmethod
    def on_init(self):
        output_path = self.get_opt_value(OUTPUT_PATH)
        if not output_path:
            output_path = f'{self.reports_folder}/.outputs/{self.unique_name}.json'
        self.output_path = output_path
        self.cmd += f' -r {self.output_path}  --exit-code 0'
