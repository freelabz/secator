import click
import yaml

from secator.decorators import task
from secator.runners import Command
from secator.definitions import OUTPUT_PATH
from secator.output_types import Vulnerability, Info


@task()
class wpprobe(Command):
    cmd = 'wpprobe'

    file_flag = '-f'
    input_flag = '-u'
    opt_prefix = '-'

    opts = {
        'mode': {
            'type': click.Choice(['scan', 'update', 'update-db']),
            'default': 'scan',
            'help': 'WPProbe mode'
        },
        'f': {
            'type': str,
            'help': 'Targets list path'
        },
        't': {
            'type': int,
            'default': 20,
            'help': 'Numbers of threads (default 20)'
        },
        'u': {
            'type': str,
            'help': 'Target url'
        }
    }

    output_types = [Vulnerability]

    install_cmd = 'go install github.com/Chocapikk/wpprobe@latest'
    install_github_handle = 'Chocapikk/wpprobe'

    @staticmethod
    def on_start(self):
        # Replace fake -mode opt by subcommand
        mode = self.get_opt_value('mode')
        self.cmd = self.cmd.replace(
            f'-mode {mode}', ''
        ).replace(
            wpprobe.cmd, f'{wpprobe.cmd} {mode}'
        ).replace(
            'None', ''
        )

        output_path = self.get_opt_value(OUTPUT_PATH)
        if not output_path:
            output_path = f'{self.reports_folder}/.outputs/{self.unique_name}.json'
        self.output_path = output_path
        self.cmd += f' -o {self.output_path}'

        if 'update-db' in self.cmd:
            self.cmd = f'{wpprobe.cmd} update-db'

    @staticmethod
    def on_cmd_done(self):
        yield Info(message=f'JSON results saved to {self.output_path}')
        with open(self.output_path, 'r') as f:
            results = yaml.safe_load(f.read())
        for name in results['plugins']:
            for plug in results['plugins'][name]:
                for severity in plug['severities']:
                    if severity != 'None':
                        for vuln in plug['severities'][severity]:
                            yield Vulnerability(
                                name=name,
                                severity=severity,
                                tags=vuln['cves'],
                                extra_data={
                                    'version': plug['version'],
                                    'auth_type': vuln['auth_type']
                                },
                                matched_at=results['url']
                            )
