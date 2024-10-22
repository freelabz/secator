import click
import os
import yaml

from secator.decorators import task 
from secator.runners import Command
from secator.output_types import Vulnerability
from secator.definitions import (OUTPUT_PATH)


@task()
class trivy(Command):
    cmd = 'trivy'  
    input_flag = None
    json_flag = '-f json'
    opts = {
        "mode": {"type": click.Choice(['image','fs','repo']), "default": "image", "help": "Trivy mode (`image`, `fs` or `repo`)"}
    }

    output_types = [Vulnerability]

    output_map = {
        Vulnerability: {
            'name': 'VulnerabilityID',
            'description': 'Description',
            'severity': lambda x: x['Severity'].lower(),
            'references': 'References'
        }
    }

    install_cmd = "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.18.3"

    @staticmethod
    def on_cmd(self):
        mode = self.get_opt_value('mode')
        jsonFlag = trivy.json_flag
        output_path = self.get_opt_value(OUTPUT_PATH)
        if not output_path:
            output_path = f'{self.reports_folder}/.outputs/{self.unique_name}.json'
        self.output_path = output_path
        self.cmd = self.cmd.replace(
			f'-mode {mode}', ''
		).replace(
            f'{trivy.json_flag}', ''
        ).replace(
			trivy.cmd, f'{trivy.cmd} {mode} {jsonFlag}  -o {self.output_path}'
		)

    def yielder(self):
        prev = self.print_item_count
        self.print_item_count = False
        list(super().yielder())
        if self.return_code != 0:
            return
        self.results = []
        if not self.output_json:
            return
        note = f'Trivy JSON result saved to {self.output_path}'
        if self.print_line:
            self._print(note)
        if os.path.exists(self.output_path):
            with open(self.output_path, 'r') as f:
                results = yaml.safe_load(f.read())
            for item in results[0]['Vulnerabilities']:
                item = self._process_item(item)
                if not item:
                    continue
                yield item
        self.print_item_count = prev