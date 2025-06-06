import distro
import getpass
import os
import platform
import re
import shutil
import tarfile
import zipfile
import io

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path

import json
import requests

from rich.table import Table

from secator.config import CONFIG
from secator.celery import IN_CELERY_WORKER_PROCESS
from secator.definitions import OPT_NOT_SUPPORTED
from secator.output_types import Info, Warning, Error
from secator.rich import console
from secator.runners import Command
from secator.utils import get_versions_from_string


class InstallerStatus(Enum):
	SUCCESS = 'SUCCESS'
	INSTALL_FAILED = 'INSTALL_FAILED'
	INSTALL_NOT_SUPPORTED = 'INSTALL_NOT_SUPPORTED'
	INSTALL_SKIPPED_OK = 'INSTALL_SKIPPED_OK'
	INSTALL_VERSION_NOT_SPECIFIED = 'INSTALL_VERSION_NOT_SPECIFIED'
	GITHUB_LATEST_RELEASE_NOT_FOUND = 'GITHUB_LATEST_RELEASE_NOT_FOUND'
	GITHUB_RELEASE_NOT_FOUND = 'RELEASE_NOT_FOUND'
	GITHUB_RELEASE_UNMATCHED_DISTRIBUTION = 'RELEASE_UNMATCHED_DISTRIBUTION'
	GITHUB_RELEASE_FAILED_DOWNLOAD = 'GITHUB_RELEASE_FAILED_DOWNLOAD'
	GITHUB_BINARY_NOT_FOUND_IN_ARCHIVE = 'GITHUB_BINARY_NOT_FOUND_IN_ARCHIVE'
	UNKNOWN_DISTRIBUTION = 'UNKNOWN_DISTRIBUTION'
	UNKNOWN = 'UNKNOWN'

	def is_ok(self):
		return self.value in ['SUCCESS', 'INSTALL_SKIPPED_OK']


@dataclass
class Distribution:
	name: str
	system: str
	pm_name: str
	pm_installer: str
	pm_finalizer: str


class ToolInstaller:
	status = InstallerStatus

	@classmethod
	def install(cls, tool_cls):
		name = tool_cls.__name__
		console.print(Info(message=f'Installing {name}'))
		status = InstallerStatus.UNKNOWN

		# Fail if not supported
		if not any(_ for _ in [
			tool_cls.install_pre,
			tool_cls.install_github_handle,
			tool_cls.install_cmd,
			tool_cls.install_post]):
			return InstallerStatus.INSTALL_NOT_SUPPORTED

		# Check PATH
		path_var = os.environ.get('PATH', '')
		if str(CONFIG.dirs.bin) not in path_var:
			console.print(Warning(message=f'Bin directory {CONFIG.dirs.bin} not found in PATH ! Binaries installed by secator will not work'))  # noqa: E501
			console.print(Warning(message=f'Run "export PATH=$PATH:{CONFIG.dirs.bin}" to add the binaries to your PATH'))

		# Install pre-required packages
		if tool_cls.install_pre:
			status = PackageInstaller.install(tool_cls.install_pre)
			if not status.is_ok():
				cls.print_status(status, name)
				return status

		# Install binaries from GH
		gh_status = InstallerStatus.UNKNOWN
		if tool_cls.install_github_handle and not CONFIG.security.force_source_install:
			gh_status = GithubInstaller.install(tool_cls.install_github_handle, version=tool_cls.install_version or 'latest')
			status = gh_status

		# Install from source
		if not gh_status.is_ok():
			if not tool_cls.install_cmd:
				status = InstallerStatus.INSTALL_SKIPPED_OK
			else:
				status = SourceInstaller.install(tool_cls.install_cmd, tool_cls.install_version)
				if not status.is_ok():
					cls.print_status(status, name)
					return status

		# Install post commands
		if tool_cls.install_post:
			post_status = SourceInstaller.install(tool_cls.install_post)
			if not post_status.is_ok():
				cls.print_status(post_status, name)
				return post_status

		cls.print_status(status, name)
		return status

	@classmethod
	def print_status(cls, status, name):
		if status.is_ok():
			console.print(Info(message=f'{name} installed successfully!'))
		elif status == InstallerStatus.INSTALL_NOT_SUPPORTED:
			console.print(Error(message=f'{name} install is not supported yet. Please install manually'))
		else:
			console.print(Error(message=f'Failed to install {name}: {status}'))


class PackageInstaller:
	"""Install system packages."""

	@classmethod
	def install(cls, config):
		"""Install packages using the correct package manager based on the distribution.

		Args:
			config (dict): A dict of package managers as keys and a list of package names as values.

		Returns:
			InstallerStatus: installer status.
		"""
		# Init status
		distribution = get_distro_config()
		if not distribution.pm_installer:
			return InstallerStatus.UNKNOWN_DISTRIBUTION

		console.print(
			Info(message=f'Detected distribution "{distribution.name}", using package manager "{distribution.pm_name}"'))

		# Construct package list
		pkg_list = []
		for managers, packages in config.items():
			if distribution.pm_name in managers.split("|") or managers == '*':
				pkg_list.extend(packages)
				break

		# Installer cmd
		cmd = distribution.pm_installer
		if CONFIG.security.autoinstall_commands and IN_CELERY_WORKER_PROCESS:
			cmd = f'flock /tmp/install.lock {cmd}'
		if getpass.getuser() != 'root':
			cmd = f'sudo {cmd}'

		if pkg_list:
			pkg_str = ''
			for pkg in pkg_list:
				if ':' in pkg:
					pdistro, pkg = pkg.split(':')
					if pdistro != distribution.name:
						continue
				pkg_str += f'{pkg} '
			console.print(Info(message=f'Installing packages {pkg_str}'))
			status = SourceInstaller.install(f'{cmd} {pkg_str}', install_prereqs=False)
			if not status.is_ok():
				return status
		return InstallerStatus.SUCCESS


class SourceInstaller:
	"""Install a tool from source."""

	@classmethod
	def install(cls, config, version=None, install_prereqs=True):
		"""Install from source.

		Args:
			cls: ToolInstaller class.
			config (dict): A dict of distros as keys and a command as value.
			version (str, optional): Version to install.
			install_prereqs (bool, optional): Install pre-requisites.

		Returns:
			Status: install status.
		"""
		install_cmd = None
		if isinstance(config, str):
			install_cmd = config
		else:
			distribution = get_distro_config()
			if not distribution.pm_installer:
				return InstallerStatus.UNKNOWN_DISTRIBUTION
			for distros, command in config.items():
				if distribution.name in distros.split("|") or distros == '*':
					install_cmd = command
					break
		if not install_cmd:
			return InstallerStatus.INSTALL_SKIPPED_OK

		# Install build dependencies if needed
		if install_prereqs:
			if 'go ' in install_cmd:
				status = PackageInstaller.install({'apt': ['golang-go'], '*': ['go']})
				if not status.is_ok():
					return status
			if 'gem ' in install_cmd:
				status = PackageInstaller.install({'apk': ['ruby', 'ruby-dev'], 'pacman': ['ruby', 'rubygems'], 'apt': ['ruby-full', 'rubygems']})  # noqa: E501
				if not status.is_ok():
					return status
			if 'git ' in install_cmd or 'git+' in install_cmd:
				status = PackageInstaller.install({'*': ['git']})
				if not status.is_ok():
					return status

		# Handle version
		if '[install_version]' in install_cmd:
			version = version or 'latest'
			install_cmd = install_cmd.replace('[install_version]', version)
		elif '[install_version_strip]' in install_cmd:
			version = version or 'latest'
			install_cmd = install_cmd.replace('[install_version_strip]', version.lstrip('v'))

		# Run command
		ret = Command.execute(install_cmd, cls_attributes={'shell': True}, quiet=False)
		return InstallerStatus.SUCCESS if ret.return_code == 0 else InstallerStatus.INSTALL_FAILED


class GithubInstaller:
	"""Install a tool from GitHub releases."""

	@classmethod
	def install(cls, github_handle, version='latest'):
		"""Find and install a release from a GitHub handle {user}/{repo}.

		Args:
			github_handle (str): A GitHub handle {user}/{repo}

		Returns:
			InstallerStatus: status.
		"""
		_, repo = tuple(github_handle.split('/'))
		release = cls.get_release(github_handle, version=version)
		if not release:
			return InstallerStatus.GITHUB_RELEASE_NOT_FOUND

		# Find the right asset to download
		system, arch, os_identifiers, arch_identifiers = cls._get_platform_identifier()
		download_url = cls._find_matching_asset(release['assets'], os_identifiers, arch_identifiers)
		if not download_url:
			console.print(Warning(message=f'Could not find a GitHub release matching distribution (system: {system}, arch: {arch}).'))  # noqa: E501
			return InstallerStatus.GITHUB_RELEASE_UNMATCHED_DISTRIBUTION

		# Download and unpack asset
		console.print(Info(message=f'Found release URL: {download_url}'))
		return cls._download_and_unpack(download_url, CONFIG.dirs.bin, repo)

	@classmethod
	def get_release(cls, github_handle, version='latest'):
		"""Get release from GitHub.

		Args:
			github_handle (str): A GitHub handle {user}/{repo}.

		Returns:
			dict: Release JSON from GitHub releases.
		"""
		if not github_handle:
			return False
		owner, repo = tuple(github_handle.split('/'))
		if version == 'latest':
			url = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
		else:
			url = f"https://api.github.com/repos/{owner}/{repo}/releases/tags/{version}"
		headers = {}
		if CONFIG.cli.github_token:
			headers['Authorization'] = f'Bearer {CONFIG.cli.github_token}'
		try:
			response = requests.get(url, headers=headers, timeout=5)
			response.raise_for_status()
			latest_release = response.json()
			return latest_release
		except requests.RequestException as e:
			console.print(Warning(message=f'Failed to fetch latest release for {github_handle}: {str(e)}'))
			if 'rate limit exceeded' in str(e):
				console.print(Warning(message='Consider setting env variable SECATOR_CLI_GITHUB_TOKEN or use secator config set cli.github_token $TOKEN.'))  # noqa: E501
			return None

	@classmethod
	def get_latest_version(cls, github_handle):
		latest_release = cls.get_release(github_handle, version='latest')
		if not latest_release:
			return None
		return latest_release['tag_name'].lstrip('v')

	@classmethod
	def _get_platform_identifier(cls):
		"""Generate lists of possible identifiers for the current platform."""
		system = platform.system().lower()
		arch = platform.machine().lower()

		# Mapping common platform.system() values to those found in release names
		os_mapping = {
			'linux': ['linux'],
			'windows': ['windows', 'win'],
			'darwin': ['darwin', 'macos', 'osx', 'mac']
		}

		# Enhanced architecture mapping to avoid conflicts
		arch_mapping = {
			'x86_64': ['amd64', 'x86_64', '64bit', 'x64'],
			'amd64': ['amd64', 'x86_64', '64bit', 'x64'],
			'aarch64': ['arm64', 'aarch64'],
			'armv7l': ['armv7', 'arm'],
			'386': ['386', 'x86', 'i386', '32bit', 'x32'],
		}

		os_identifiers = os_mapping.get(system, [])
		arch_identifiers = arch_mapping.get(arch, [])
		return system, arch, os_identifiers, arch_identifiers

	@classmethod
	def _find_matching_asset(cls, assets, os_identifiers, arch_identifiers):
		"""Find a release asset matching the current platform more precisely."""
		potential_matches = []

		for asset in assets:
			asset_name = asset['name'].lower()
			if any(os_id in asset_name for os_id in os_identifiers) and \
			   any(arch_id in asset_name for arch_id in arch_identifiers):
				potential_matches.append(asset['browser_download_url'])

		# Preference ordering for file formats, if needed
		preferred_formats = ['.tar.gz', '.zip']

		for format in preferred_formats:
			for match in potential_matches:
				if match.endswith(format):
					return match

		if potential_matches:
			return potential_matches[0]

	@classmethod
	def _download_and_unpack(cls, url, destination, repo_name):
		"""Download and unpack a release asset.

		Args:
			cls (Runner): Task class.
			url (str): GitHub release URL.
			destination (str): Local destination.
			repo_name (str): GitHub repository name.

		Returns:
			InstallerStatus: install status.
		"""
		console.print(Info(message=f'Downloading and unpacking to {destination}...'))
		response = requests.get(url, timeout=5)
		if not response.status_code == 200:
			return InstallerStatus.GITHUB_RELEASE_FAILED_DOWNLOAD

		# Create a temporary directory to extract the archive
		date_str = datetime.now().strftime("%Y%m%d_%H%M%S")
		temp_dir = os.path.join("/tmp", f'{repo_name}_{date_str}')
		os.makedirs(temp_dir, exist_ok=True)

		console.print(Info(message=f'Extracting binary to {temp_dir}...'))
		if url.endswith('.zip'):
			with zipfile.ZipFile(io.BytesIO(response.content)) as zip_ref:
				zip_ref.extractall(temp_dir)
		elif url.endswith('.tar.gz'):
			with tarfile.open(fileobj=io.BytesIO(response.content), mode='r:gz') as tar:
				tar.extractall(path=temp_dir)
		else:
			with Path(f'{temp_dir}/{repo_name}').open('wb') as f:
				f.write(response.content)

		# For archives, find and move the binary that matches the repo name
		binary_path = cls._find_binary_in_directory(temp_dir, repo_name)
		if binary_path:
			os.chmod(binary_path, 0o755)  # Make it executable
			destination = os.path.join(destination, repo_name)
			console.print(Info(message=f'Moving binary to {destination}...'))
			shutil.move(binary_path, destination)  # Move the binary
			return InstallerStatus.SUCCESS
		else:
			console.print(Error(message='Binary matching the repository name was not found in the archive.'))
			return InstallerStatus.GITHUB_BINARY_NOT_FOUND_IN_ARCHIVE

	@classmethod
	def _find_binary_in_directory(cls, directory, binary_name):
		"""Search for the binary in the given directory that matches the repository name."""
		for root, _, files in os.walk(directory):
			for file in files:
				# Match the file name exactly with the repository name
				if file == binary_name:
					return os.path.join(root, file)
		return None


def which(command):
	"""Run which on a command.

	Args:
		command (str): Command to check.

	Returns:
		secator.Command: Command instance.
	"""
	return Command.execute(f'which {command}', quiet=True, print_errors=False)


def get_version(version_cmd):
	"""Run version command and match first version number found.

	Args:
		version_cmd (str): Command to get the version.

	Returns:
		tuple[str]: Version string, return code.
	"""
	from secator.runners import Command
	ret = Command.execute(version_cmd, quiet=True, print_errors=False)
	versions = get_versions_from_string(ret.output)
	if not versions:
		return None
	return versions[0]


def parse_version(ver):
	from packaging import version as _version
	try:
		return _version.parse(ver)
	except _version.InvalidVersion:
		version_regex = re.compile(r'(\d+\.\d+(?:\.\d+)?)')
		match = version_regex.search(ver)
		if match:
			return _version.parse(match.group(1))
		return None


def get_version_info(name, version_flag=None, install_github_handle=None, install_cmd=None, install_version=None, version=None, bleeding=False):  # noqa: E501
	"""Get version info for a command.

	Args:
		name (str): Command name.
		version_flag (str): Version flag.
		install_github_handle (str): Github handle.
		install_cmd (str): Install command.
		install_version (str): Install version.
		version (str): Existing version.
		bleeding (bool): Bleeding edge.

	Return:
		dict: Version info.
	"""
	from secator.installer import GithubInstaller
	info = {
		'name': name,
		'installed': False,
		'version': version,
		'version_cmd': None,
		'latest_version': None,
		'install_version': None,
		'location': None,
		'status': '',
		'outdated': False,
		'bleeding': False,
		'source': None,
		'errors': [],
	}

	# Get binary path
	location = which(name).output
	if not location or not Path(location).exists():
		info['installed'] = False
		info['status'] = 'missing'
		return info
	info['location'] = location
	info['installed'] = True

	# Get latest / recommanded version
	latest_version = None
	if install_version and not bleeding:
		ver = parse_version(install_version)
		info['latest_version'] = str(ver)
		info['install_version'] = str(ver)
		info['source'] = 'supported'
		latest_version = str(ver)
	else:
		latest_version = None
		if not CONFIG.offline_mode:
			if install_github_handle:
				latest_version = GithubInstaller.get_latest_version(install_github_handle)
				info['latest_version'] = latest_version
				info['source'] = 'github'
			elif install_cmd and install_cmd.startswith('pip'):
				req = requests.get(f'https://pypi.python.org/pypi/{name}/json')
				version = parse_version('0')
				if req.status_code == requests.codes.ok:
					j = json.loads(req.text.encode(req.encoding))
					releases = j.get('releases', [])
					for release in releases:
						ver = parse_version(release)
						if ver and not ver.is_prerelease and not ver.is_postrelease and not ver.is_devrelease:
							version = max(version, ver)
							latest_version = str(version)
							info['source'] = 'pypi'
			else:
				info['errors'].append('Cannot get latest version for query method (github, pip) is available')
	info['latest_version'] = f'v{latest_version}' if install_version and install_version.startswith('v') else latest_version  # noqa: E501

	# Get current version
	version_flag = None if version_flag == OPT_NOT_SUPPORTED else version_flag
	if version_flag and not version:
		version_cmd = f'{name} {version_flag}'
		info['version_cmd'] = version_cmd
		version = get_version(version_cmd)
		info['version'] = version
		if not version:
			info['errors'].append(f'Error fetching version for command. Version command: {version_cmd}')
			info['status'] = 'version fetch error'
			return info

	# Check if up-to-date
	if version and latest_version:
		outdated = parse_version(version) < parse_version(latest_version)
		equal = parse_version(version) == parse_version(latest_version)
		if outdated:
			info['status'] = 'outdated'
			info['outdated'] = True
		elif equal:
			info['status'] = 'latest'
		else:
			info['status'] = 'bleeding'
			info['bleeding'] = True
			if install_version:
				info['errors'].append(f'Version {version} is greather than the recommended version {latest_version}')
			else:
				info['errors'].append(f'Version {version} is greather than the latest version {latest_version}')
	elif not version:
		info['status'] = 'current unknown'
	elif not latest_version:
		info['status'] = 'latest unknown'
		if CONFIG.offline_mode:
			info['status'] += r' [dim orange1]\[offline][/]'

	return info


def get_distro_config():
	"""Detects the system's package manager based on the OS distribution and return the default installation command."""

	# If explicitely set by the user, use that one
	package_manager_variable = os.environ.get('SECATOR_PACKAGE_MANAGER')
	if package_manager_variable:
		return package_manager_variable
	installer = None
	finalizer = None
	system = platform.system()
	distrib = system

	if system == "Linux":
		distrib = distro.like() or distro.id()
		distrib = distrib.split(' ')[0] if distrib else None

		if distrib in ["ubuntu", "debian", "linuxmint", "popos", "kali"]:
			installer = "apt install -y --no-install-recommends"
			finalizer = "rm -rf /var/lib/apt/lists/*"
		elif distrib in ["arch", "manjaro", "endeavouros"]:
			installer = "pacman -S --noconfirm --needed"
		elif distrib in ["alpine"]:
			installer = "apk add --no-cache"
		elif distrib in ["fedora"]:
			installer = "dnf install -y"
			finalizer = "dnf clean all"
		elif distrib in ["centos", "rhel", "rocky", "alma"]:
			installer = "yum -y"
			finalizer = "yum clean all"
		elif distrib in ["opensuse", "sles"]:
			installer = "zypper -n"
			finalizer = "zypper clean --all"

	elif system == "Darwin":  # macOS
		installer = "brew install"

	elif system == "Windows":
		if shutil.which("winget"):
			installer = "winget install --disable-interactivity"
		elif shutil.which("choco"):
			installer = "choco install -y --no-progress"
		else:
			installer = "scoop"  # Alternative package manager for Windows

	if not installer:
		console.print(Error(message=f'Could not find installer for your distribution (system: {system}, distrib: {distrib})'))  # noqa: E501

	manager = installer.split(' ')[0] if installer else ''
	config = Distribution(
		pm_installer=installer,
		pm_finalizer=finalizer,
		pm_name=manager,
		name=distrib,
		system=system
	)
	return config


def fmt_health_table_row(version_info, category=None):
	name = version_info['name']
	version = version_info['version']
	if version:
		version = version.lstrip('v')
	status = version_info['status']
	installed = version_info['installed']
	latest_version = version_info['latest_version']
	if latest_version:
		latest_version = latest_version.lstrip('v')
	source = version_info.get('source')
	name_str = f'[magenta]{name:<13}[/]'

	# Format version row
	_version = version or ''
	_version = f'[bold green]{_version:<10}[/]'
	if status == 'latest':
		_version += f' [bold green](latest {source})[/]'
	elif status == 'bleeding':
		msg = f'bleeding >{latest_version} {source}' if source else f'bleeding >{latest_version}'
		_version += f' [bold orange1]({msg})[/]'
	elif status == 'outdated':
		_version += ' [bold red](outdated)[/]'
		if latest_version:
			_version += f' [dim](<{latest_version} {source})[/]'
	elif status == 'missing':
		_version = '[bold red]missing[/]'
	elif status == 'missing_ok':
		_version = '[dim green]not installed        [/]'
	elif status == 'ok':
		_version = '[bold green]ok        [/]'
	elif status == 'version fetch error':
		_version = '[bold orange1]unknown[/]    [dim](current unknown)[/]'
	elif status:
		if not version and installed:
			_version = '[bold green]ok        [/]'
		_version += f' [dim]({status}[/])'

	row = (name_str, _version)
	return row


def get_health_table():
	table = Table(box=None, show_header=False)
	for col in ['name', 'version']:
		table.add_column(col)
	return table
