import click

from pathlib import Path

from secator.config import CONFIG
from secator.decorators import task
from secator.runners import Command
from secator.definitions import (PATH, URL, STRING, OPT_SPACE_SEPARATED, GCS_URL, ADDONS_ENABLED, SLUG)
from secator.utils import caml_to_snake
from secator.output_types import Tag, Info, Warning, Error
from secator.rich import console
from secator.serializers import JSONSerializer

TRUFFLEHOG_MODES = [
    'git',
    'github',
    'gitlab',
    's3',
    'filesystem',
    'gcs',
    'docker',
    'postman',
    'jenkins',
    'elasticsearch',
    'huggingface',
    'syslog',
]


@task()
class trufflehog(Command):
    """Tool for finding secrets in git repositories and filesystems using TruffleHog."""
    cmd = 'trufflehog'
    tags = ['secret', 'scan']
    input_types = [PATH, URL, STRING, GCS_URL, SLUG]
    item_loaders = [JSONSerializer()]
    input_flag = None
    file_flag = OPT_SPACE_SEPARATED
    json_flag = '--json'
    opt_prefix = '--'
    opts = {
        'mode': {
            'type': click.Choice(TRUFFLEHOG_MODES),
            'help': f'Scan mode ({", ".join(TRUFFLEHOG_MODES)})',
            'internal': True
        },
        'status': {'type': str, 'help': 'Results status (verified, unknown, unverified, filtered_unverified)'},
        'concurrency': {'type': int, 'help': 'Number of concurrent workers'},
        'config': {'type': str, 'short': 'config', 'help': 'Config file path'},
        'git_branch': {'type': str, 'help': 'Branch to scan (git mode only)'},
        'git_depth': {'type': int, 'help': 'Commit depth to scan (git mode only)'},
        'git_since_commit': {'type': str, 'help': 'Scan commits starting from this commit'},
        'git_max_depth': {'type': int, 'help': 'Maximum depth of commits to scan'},
        'jenkins_username': {'type': str, 'help': 'Jenkins username to use when --mode jenkins'},
        'jenkins_password': {'type': str, 'help': 'Jenkins password to use when --mode jenkins'},
        'postman_collection_id': {'type': str, 'help': 'Postman collection ID to use when --mode postman'},
        'postman_token': {'type': str, 'help': 'Postman API token to use when --mode postman'},
        'postman_workspace_id': {'type': str, 'help': 'Postman workspace ID to use when --mode postman'},
        'gitlab_token': {'type': str, 'help': 'Gitlab token to use when --mode gitlab'},
        'gitlab_endpoint': {'type': str, 'default': 'https://gitlab.com', 'help': 'Gitlab endpoint to use when --mode gitlab', 'internal': True},  # noqa: E501
        'elasticsearch_nodes': {'type': str, 'help': 'Elasticsearch nodes (space separated) to use when --mode elasticsearch'},  # noqa: E501
        'elasticsearch_service_token': {'type': str, 'help': 'Elasticsearch service token to use when --mode elasticsearch'},  # noqa: E501
        'elasticsearch_cloud_id': {'type': str, 'help': 'Elasticsearch cloud ID to use when --mode elasticsearch'},
        'elasticsearch_api_key': {'type': str, 'help': 'Elasticsearch API key to use when --mode elasticsearch'},
    }
    opt_key_map = {
        'jenkins_username': '--username',
        'jenkins_password': '--password',
        'postman_collection_id': '--collection-id',
        'postman_token': '--token',
        'postman_workspace_id': '--workspace-id',
        'git_branch': '--branch',
        'git_depth': '--depth',
        'git_since_commit': '--since-commit',
        'git_max_depth': '--max-depth',
        'gitlab_token': '--token',
        'gitlab_endpoint': '--endpoint',
        'elasticsearch_nodes': '--nodes',
        'elasticsearch_service_token': '--service-token',
        'elasticsearch_cloud_id': '--cloud-id',
        'elasticsearch_api_key': '--api-key',
        'status': '--results',
    }
    output_types = [Tag, Info]
    ignore_return_code = True
    install_version = 'v3.91.0'
    install_cmd = (
        f'git clone https://github.com/trufflesecurity/trufflehog.git '
        f'{CONFIG.dirs.share}/trufflehog_[install_version] || true && '
        f'cd {CONFIG.dirs.share}/trufflehog_[install_version] && go build -o trufflehog . && '
        f'mv {CONFIG.dirs.share}/trufflehog_[install_version]/trufflehog {CONFIG.dirs.bin}'
    )
    github_handle = 'trufflesecurity/trufflehog'

    @staticmethod
    def before_init(self):
        blob_folder = f'{self.reports_folder}/.inputs'
        del_indexes = []
        gcs_objects = False
        for i, input in enumerate(self.inputs):
            if input.startswith('gs://'):
                if not ADDONS_ENABLED['gcs']:
                    raise Exception('GCS addon is not installed. Please install it using `secator install addons gcs`.')
                gcs_objects = True
                from secator.hooks.gcs import download_blob
                split_input = input.split('/')
                bucket_name, source_blob_name = split_input[2], '/'.join(split_input[3:])
                destination_file_name = f'{blob_folder}/{source_blob_name}'
                download_blob(bucket_name, source_blob_name, destination_file_name)
                del_indexes.append(i)
        for i in reversed(del_indexes):
            del self.inputs[i]
        if gcs_objects:
            self.inputs.append(blob_folder)

    @staticmethod
    def on_cmd(self):
        mode = self.get_opt_value('mode')
        new_input = None
        submode = None
        input = self.inputs[0] if self.inputs else None
        if mode and mode not in TRUFFLEHOG_MODES:
            raise Exception(f'Invalid mode: {mode}')
        if not mode and input:
            git_path = Path(input).joinpath('.git')
            if git_path.exists():
                mode = 'git'
                submode = 'local'
            elif Path(input).exists():
                mode = 'filesystem'
            elif input.startswith('https://github.com/'):
                mode = 'github'
                len_args = len(input.split('/'))
                if len_args == 4:
                    submode = 'org'
                    new_input = input.split('/')[-1]
                elif len_args == 5:
                    submode = 'repo'
                    new_input = '/'.join(input.split('/')[-2:])
            elif input.startswith('https://gitlab.com/'):
                mode = 'gitlab'

            if mode:
                console.print(Info(message=f'Auto mode detected: {mode} for input: {input}'))
            else:
                error = (f'Could not determine mode for input "{input}". Please specify the mode manually using the --mode option')  # noqa: E501
                raise Exception(error)

        # Add correct option
        mode_to_option = {
            'github_org': '--org',
            'github_repo': '--repo',
            'git': None,
            'gitlab': '--repo',
            's3': '--bucket',
            'gcs': '--cloud-environment --project-id',
            'docker': '--image',
            'jenkins': '--url',
            None: None,
        }
        submode_to_option = {
            'local': 'file://',
            'org': '--org ',
            'repo': '--repo ',
            None: None,
        }
        if new_input:
            console.print(Info(message=f'Replacing input {input} with {new_input}'))
            self.cmd = self.cmd.replace(input, f'{new_input}')
            input = new_input
        submode_option = submode_to_option.get(submode)
        if submode_option:
            self.cmd = self.cmd.replace(input, f'{submode_option}{input}')
        option = mode_to_option.get(mode)
        if option:
            self.cmd = self.cmd.replace(input, f'{option} {input}')
        if f'trufflehog {mode}' not in self.cmd:
            self.cmd = self.cmd.replace('trufflehog', f'trufflehog {mode}', 1)

    @staticmethod
    def on_json_loaded(self, item):
        level = item.get('level')
        if level:
            msg = item.get('msg', '').capitalize()
            if level.startswith('info'):
                yield Info(message=msg)
            elif msg == 'Error running scan':
                error = item.get('error')
                msg += ' - ' + error if error else ''
                yield Error(message=msg)
            return

        if 'SourceMetadata' not in item:
            return item

        rule_id = caml_to_snake(item.get('DetectorName', 'Unknown'))
        source_metadata = item.get('SourceMetadata', {}).get('Data', {})
        raw = item.get('RawV2') or item.get('Raw')
        detector_data = {caml_to_snake(k): v for k, v in item.items() if k not in ['SourceMetadata', 'Raw', 'RawV2']}
        data = {caml_to_snake(k): v for k, v in source_metadata[list(source_metadata.keys())[0]].items()}
        if 'timestamp' in data:
            del data['timestamp']
        subtype = list(source_metadata.keys())[0].lower()
        extra_data = {
            'subtype': subtype,
            'detector_data': {caml_to_snake(k): v for k, v in detector_data.items()}
        }
        extra_data.update({caml_to_snake(k): v for k, v in data.items()})
        match = ''
        repo_path = data.get('repository', '')
        if 'file://' in repo_path:
            repo_path = repo_path.replace('file://', '')
        file = data.get('file')
        line_no = data.get('line')
        link = data.get('link')
        if file:
            match += file
        if line_no:
            match += f":{line_no}"
        if link:
            match = link
        if repo_path and subtype != 'github':
            match = repo_path + '/' + match

        if not match:
            console.print(Warning(message=f'Could not determine match for subtype: {subtype}'))
            match = self.inputs[0]

        item_extra_data = item.get('ExtraData') or {}
        rtype = item_extra_data.get('resource_type')
        name = rule_id.lower()
        if rtype:
            name = f"{name}_{rtype.lower().replace(' ', '_')}"
        yield Tag(
            category='secret',
            name=name,
            value=raw,
            match=match,
            extra_data=extra_data
        )
