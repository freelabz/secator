import click
import os
import json

from secator.config import CONFIG
from secator.decorators import task
from secator.runners import Command
from secator.definitions import (OUTPUT_PATH, PATH, URL, STRING)
from secator.utils import caml_to_snake
from secator.output_types import Tag, Info, Error


@task()
class trufflehog(Command):
    """Tool for finding secrets in git repositories and filesystems using TruffleHog."""
    cmd = 'trufflehog'
    tags = ['secret', 'scan']

    # Input types include PATH, URL and STRING to support local files and git URLs
    input_types = [PATH, URL, STRING]

    input_flag = None
    json_flag = '--json'
    opt_prefix = '--'
    opts = {
        'mode': {
            'type': click.Choice(['git', 'filesystem', 'dir']),
            'default': 'filesystem',
            'help': 'Scan mode: git or filesystem',
            'internal': True
        },
        'only_verified': {'is_flag': True, 'help': 'Only output verified secrets'},
        'concurrency': {'type': int, 'help': 'Number of concurrent workers'},
        'config': {'type': str, 'short': 'config', 'help': 'Config file path'},
        'branch': {'type': str, 'help': 'Branch to scan (git mode only)'},
        'depth': {'type': int, 'help': 'Commit depth to scan (git mode only)'},
        'since_commit': {'type': str, 'help': 'Scan commits starting from this commit'},
        'max_depth': {'type': int, 'help': 'Maximum depth of commits to scan'},
    }
    output_types = [Tag]
    ignore_return_code = True

    install_pre = {
        'apt': ['git', 'golang'],
        'apk': ['git', 'go'],
        'pacman': ['git', 'go'],
        '*': ['git', 'go']
    }
    install_version = 'main'
    install_cmd = (
        f'git clone https://github.com/trufflesecurity/trufflehog.git '
        f'{CONFIG.dirs.share}/trufflehog_[install_version] || true && '
        f'cd {CONFIG.dirs.share}/trufflehog_[install_version] && go build -o trufflehog . && '
        f'mv {CONFIG.dirs.share}/trufflehog_[install_version]/trufflehog {CONFIG.dirs.bin}'
    )
    install_github_handle = 'trufflesecurity/trufflehog'

    @staticmethod
    def on_cmd(self):
        mode = self.get_opt_value('mode')

        # Compatibility: 'dir' -> 'filesystem'
        if mode == 'dir':
            mode = 'filesystem'

        # Add file:// prefix for local paths in git mode
        if mode == 'git':
            for target in self.inputs:
                # Only for existing files/dirs not starting with file://
                if os.path.exists(target) and not target.startswith('file://'):
                    abs_path = os.path.abspath(target)
                    if target in self.cmd:
                        self.cmd = self.cmd.replace(target, f'file://{abs_path}')

        # Build command structure: 'trufflehog' -> 'trufflehog <mode>'
        if f'trufflehog {mode}' not in self.cmd:
            self.cmd = self.cmd.replace('trufflehog', f'trufflehog {mode}', 1)

        # Output Redirection and Shell Mode
        self.shell = True
        output_path = self.get_opt_value(OUTPUT_PATH)
        if not output_path:
            output_path = f'{self.reports_folder}/.outputs/{self.unique_name}.json'
        self.output_path = output_path

        if '>' not in self.cmd:
            self.cmd += f' > {self.output_path}'

    @staticmethod
    def on_cmd_done(self):
        if not os.path.exists(self.output_path):
            yield Error(message=f'Could not find JSON results in {self.output_path}')
            return

        yield Info(message=f'JSON results saved to {self.output_path}')

        if os.stat(self.output_path).st_size == 0:
            return

        with open(self.output_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    result = json.loads(line)

                    rule_id = result.get('DetectorName', 'Unknown')
                    source_metadata = result.get('SourceMetadata', {}).get('Data', {})

                    file_path = "unknown"
                    line_no = ""

                    if 'Filesystem' in source_metadata:
                        fs_data = source_metadata['Filesystem']
                        file_path = fs_data.get('file', 'unknown')
                        line_no = fs_data.get('line', '')
                    elif 'Git' in source_metadata:
                        git_data = source_metadata['Git']
                        file_path = git_data.get('file', 'unknown')
                        line_no = git_data.get('line', '')

                    match_str = f"{file_path}"
                    if line_no:
                        match_str += f":{line_no}"

                    extra = {caml_to_snake(k): v for k, v in result.items() if k not in ['SourceMetadata', 'Raw']}

                    if 'Redacted' in result:
                        extra['secret_snippet'] = result['Redacted']

                    if result.get('Verified') is True:
                        rule_id = f"{rule_id} (VERIFIED)"

                    yield Tag(
                        name=rule_id,
                        category='secret',
                        match=match_str,
                        extra_data=extra
                    )

                except json.JSONDecodeError:
                    continue
