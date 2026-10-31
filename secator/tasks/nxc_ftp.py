import shutil

from pathlib import Path

from secator.decorators import task
from secator.definitions import HOST, HOST_PORT, IP, STRING, THREADS, HEADER, DELAY, FOLLOW_REDIRECT, PROXY, RATE_LIMIT, RETRIES, TIMEOUT, USER_AGENT, OPT_NOT_SUPPORTED  # noqa: E501
from secator.output_types import Vulnerability, Tag, Warning
from secator.tasks._categories import Vuln
from secator.utils import autodetect_type


@task()
class nxc_ftp(Vuln):
    """NetExec (a.k.a nxc) is a network service exploitation tool that helps automate assessing the security of large networks. FTP Submodule."""  # noqa: E501
    cmd = 'nxc ftp'
    encoding = 'ansi'  # nxc colorizes output; strip ANSI before parsing (CI forces color)
    input_chunk_size = 1
    input_types = [HOST, HOST_PORT, IP, STRING]
    output_types = [Vulnerability, Tag]
    ignore_return_code = True
    opt_prefix = '--'
    opts = {
        'username': {'type': str, 'short': 'u', 'default': 'anonymous', 'help': 'Username'},
        'password': {'type': str, 'short': 'p', 'default': '', 'help': 'Password'},
        'ftp_port': {'type': int, 'default': 21, 'help': 'FTP port'},
        'dns_server': {'type': str, 'default': None, 'help': 'DNS server (default from system)'},
        'dns_timeout': {'type': int, 'default': 3, 'help': 'DNS query timeout in seconds'},
        'cred_id': {'type': str, 'default': None, 'help': 'Database credential ID(s) to use for authentication'},
        'ignore_pw_decoding': {'is_flag': True, 'help': 'Ignore non UTF-8 characters when decoding the password file'},
        'no_bruteforce': {'is_flag': True, 'help': 'No spray when using file for username and password (user1 => password1, user2 => password2)'},  # noqa: E501
        'continue_on_success': {'is_flag': True, 'help': 'Continues auth attempts even after successes'},
        'kerberos': {'is_flag': True, 'help': 'Use Kerberos authentication'},
        'module': {'type': str, 'help': 'Module to use'},
        'module_option': {'type': str, 'help': 'Module option'},
        'list': {'is_flag': True, 'short': 'ls', 'help': 'List all files (including hidden) in the directory'},
        'get': {'type': str, 'help': 'Download a file'},
        'put': {'type': str, 'help': 'Upload a file (format: LOCAL_FILE REMOTE_FILE)'}
    }
    opt_key_map = {
        'username': '-u',
        'password': '-p',
        'module_option': '-o',
        'list': 'ls',
        'ftp_port': 'port',
        THREADS: 'threads',
        HEADER: OPT_NOT_SUPPORTED,
        DELAY: 'jitter',
        FOLLOW_REDIRECT: OPT_NOT_SUPPORTED,
        PROXY: OPT_NOT_SUPPORTED,
        RATE_LIMIT: OPT_NOT_SUPPORTED,
        RETRIES: OPT_NOT_SUPPORTED,
        TIMEOUT: 'timeout',
        USER_AGENT: OPT_NOT_SUPPORTED,
    }
    opt_value_map = {
        DELAY: lambda x: f'{str(x)}-{str(x)}',
    }
    github_handle = 'Pennyw0rth/NetExec'
    install_github_bin = False
    install_version = "30cf1465"
    install_cmd = "pipx install --force git+https://github.com/Pennyw0rth/NetExec@[install_version]"

    @staticmethod
    def on_cmd_opts(self, opts):
        if len(self.inputs) > 1:  # parent
            return opts
        if self.inputs:
            self.full_target = self.inputs[0]
        if self.inputs and autodetect_type(self.inputs[0]) == HOST_PORT:
            host, port = tuple(self.inputs[0].split(':'))
            self.cmd = self.cmd.replace(self.inputs[0], host)
            self.inputs[0] = host
            opts['ftp_port']['value'] = int(port)
        self.login = False
        return opts

    @staticmethod
    def on_line(self, line):
        list_mode = self.get_opt_value('list')
        get_mode = self.get_opt_value('get')
        put_mode = self.get_opt_value('put')
        any_mode = (list_mode or get_mode or put_mode)

        # Anonymous login (vuln)
        if 'Anonymous Login!' in line and not any_mode:
            yield Vulnerability(
                name='FTP - Credential Weakness',
                description='Users can log in with a common username like "anonymous" or "ftp".',
                impact=(
                    'Any remote user may connect and authenticate to the server without providing a password or '
                    'unique credentials. This allows the user to access any files made available by the FTP server.'
                ),
                remediation=(
                    'Disable anonymous FTP if it is not required. '
                    'Routinely check the FTP server to ensure that sensitive content is not being made available.'
                ),
                cvss_vec='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
                cvss_score=5.3,
                severity='medium',
                confidence='high',
                matched_at=self.full_target,
                tags=['network', 'ftp', 'unauth', 'default-login'],
            )

        # Errors
        error = '[-]' in line or 'ERROR' in line
        if error:
            if '[-]' in line:
                yield Warning(message=line.split('[-]')[-1].strip())
            else:
                yield Warning(message=line.split('ERROR')[-1].strip())

        # Login status. NetExec logs a login success as `[+] <user>:<pass>`
        # (optionally with "- Anonymous Login!"). Only treat the line as a
        # successful login when it carries the `<user>:<pass>` shape, so a
        # server reply or password that happens to contain `[+]` does not
        # produce a false login tag.
        info = '[+]' in line
        if info and not any_mode:
            username = self.get_opt_value('username')
            password = self.get_opt_value('password')
            success_marker = line.split('[+]')[-1].strip()
            if not success_marker.startswith(f'{username}:'):
                yield line
                return
            message = f'{username}:{password}'
            yield Tag(
                category='info',
                match=self.full_target,
                name='ftp_login_successful',
                value=message,
                extra_data={
                    'username': username,
                    'password': password,
                    'target': self.full_target
                },
                tags=['network', 'ftp', 'login'],
            )

        # File list
        if list_mode and line.startswith('FTP'):
            split = [c for c in line.split(' ') if c]
            if len(split) == 13:  # file / dir listing
                _, _, _, _, perms, lcount, uid, gid, size, mod_month, mod_day, mod_time, name = tuple(split)
                tag_name = 'ftp_dir' if perms.startswith('d') else 'ftp_file'
                if name in ['.', '..']:
                    return
                yield Tag(
                    category='info',
                    match=self.full_target,
                    name=tag_name,
                    value=name,
                    extra_data={
                        'permissions': perms,
                        'link_count': lcount,
                        'uid': uid,
                        'gid': gid,
                        'size': size,
                        'last_updated': f'{mod_month} {mod_day} {mod_time}'
                    },
                    tags=['network', 'ftp', 'directory' if tag_name == 'ftp_dir' else 'file'],
                )
        yield line

    @staticmethod
    def on_cmd_done(self):
        # File get
        fname = self.get_opt_value('get')
        downloaded_success = 'Downloaded' in self.output
        if fname and downloaded_success:
            # NetExec saves the downloaded file in the working directory under its
            # basename, regardless of the remote path passed to --get.
            local_name = Path(fname).name
            if not Path(local_name).exists():
                yield Warning(message=f'File {local_name} not found.')
                return
            output_path = f'{self.reports_folder}/.outputs/{local_name}'
            shutil.move(local_name, output_path)
            with open(output_path) as f:
                content = f.read()
                yield Tag(
                    category='info',
                    match=self.full_target,
                    name='ftp_file_content',
                    value=content.rstrip(),
                    extra_data={
                        'path': Path(output_path).resolve()
                    },
                    tags=['network', 'ftp', 'file', 'content'],
                )
