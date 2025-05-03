import click
import yaml

from secator.decorators import task
from secator.runners import Command
from secator.definitions import OUTPUT_PATH, THREADS, URL
from secator.output_types import Vulnerability, Tag, Info, Warning
from secator.tasks._categories import OPTS


@task()
class wpprobe(Command):
    """Fast wordpress plugin enumeration tool."""
    cmd = 'wpprobe'
    tags = ['vuln', 'scan', 'wordpress']
    file_flag = '-f'
    input_flag = '-u'
    input_types = [URL]
    opt_prefix = '-'
    opts = {
        'mode': {'type': click.Choice(['scan', 'update', 'update-db']), 'default': 'scan', 'help': 'WPProbe mode', 'required': True, 'internal': True},  # noqa: E501
        'output_path': {'type': str, 'default': None, 'help': 'Output JSON file path', 'internal': True, 'display': False},  # noqa: E501
    }
    meta_opts = {
        THREADS: OPTS[THREADS]
    }
    opt_key_map = {
        THREADS: 't'
    }
    output_types = [Vulnerability, Tag]
    install_version = 'v0.5.6'
    install_cmd = 'go install github.com/Chocapikk/wpprobe@[install_version]'
    install_github_handle = 'Chocapikk/wpprobe'
    install_post = {
        '*': 'wpprobe update && wpprobe update-db'
    }

    @staticmethod
    def on_cmd(self):
        mode = self.get_opt_value('mode')
        if mode == 'update' or mode == 'update-db':
            self.cmd = f'{wpprobe.cmd} {mode}'
            return
        self.cmd = self.cmd.replace(wpprobe.cmd, f'{wpprobe.cmd} {mode}')
        output_path = self.get_opt_value(OUTPUT_PATH)
        if not output_path:
            output_path = f'{self.reports_folder}/.outputs/{self.unique_name}.json'
        self.output_path = output_path
        self.cmd += f' -o {self.output_path}'

    @staticmethod
    def on_cmd_done(self):
        if not self.get_opt_value('mode') == 'scan':
            return
        yield Info(message=f'JSON results saved to {self.output_path}')
        with open(self.output_path, 'r') as f:
            results = yaml.safe_load(f.read())
            if not results or 'url' not in results:
                yield Warning(message='No results found !')
                return
            url = results['url']
            for plugin_name, plugin_data in results['plugins'].items():
                for plugin_data_version in plugin_data:
                    plugin_version = plugin_data_version['version']
                    yield Tag(
                        name=f'Wordpress plugin - {plugin_name} {plugin_version}',
                        match=url,
                        extra_data={
                            'name': plugin_name,
                            'version': plugin_version
                        }
                    )
                    severities = plugin_data_version.get('severities', {})
                    for severity, severity_data in severities.items():
                        if severity == 'None':
                            severity = 'unknown'
                        for item in severity_data:
                            for vuln in item['vulnerabilities']:
                                auth_type = item.get('auth_type')
                                extra_data = {
                                    'plugin_name': plugin_name,
                                    'plugin_version': plugin_version,
                                }
                                if auth_type:
                                    extra_data['auth_type'] = auth_type
                                yield Vulnerability(
                                    name=vuln['title'],
                                    id=vuln['cve'],
                                    severity=severity,
                                    cvss_score=vuln['cvss_score'],
                                    tags=[plugin_name],
                                    reference=vuln['cve_link'],
                                    extra_data=extra_data,
                                    matched_at=url,
                                    confidence='high'
                                )
