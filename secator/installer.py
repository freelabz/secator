
import requests
import os
import platform
import shutil
import tarfile
import zipfile
import io

from rich.table import Table

from secator.rich import console
from secator.runners import Command
from secator.config import CONFIG


class ToolInstaller:

	@classmethod
	def install(cls, tool_cls):
		"""Install a tool.

		Args:
			cls: ToolInstaller class.
			tool_cls: Tool class (derived from secator.runners.Command).

		Returns:
			bool: True if install is successful, False otherwise.
		"""
		console.print(f'[bold gold3]:wrench: Installing {tool_cls.__name__}')
		success = False

		if not tool_cls.install_github_handle and not tool_cls.install_cmd:
			console.print(
				f'[bold red]{tool_cls.__name__} install is not supported yet. Please install it manually.[/]')
			return False

		if tool_cls.install_github_handle:
			success = GithubInstaller.install(tool_cls.install_github_handle)

		if tool_cls.install_cmd and not success:
			success = SourceInstaller.install(tool_cls.install_cmd)

		if success:
			console.print(
				f'[bold green]:tada: {tool_cls.__name__} installed successfully[/] !')
		else:
			console.print(
				f'[bold red]:exclamation_mark: Failed to install {tool_cls.__name__}.[/]')
		return success


class SourceInstaller:
	"""Install a tool from source."""

	@classmethod
	def install(cls, install_cmd):
		"""Install from source.

		Args:
			cls: ToolInstaller class.
			install_cmd (str): Install command.

		Returns:
			bool: True if install is successful, False otherwise.
		"""
		ret = Command.execute(install_cmd, cls_attributes={'shell': True})
		return ret.return_code == 0


class GithubInstaller:
	"""Install a tool from GitHub releases."""

	@classmethod
	def install(cls, github_handle):
		"""Find and install a release from a GitHub handle {user}/{repo}.

		Args:
			github_handle (str): A GitHub handle {user}/{repo}

		Returns:
			bool: True if install is successful, False otherwise.
		"""
		_, repo = tuple(github_handle.split('/'))
		latest_release = cls.get_latest_release(github_handle)
		if not latest_release:
			return False

		# Find the right asset to download
		os_identifiers, arch_identifiers = cls._get_platform_identifier()
		download_url = cls._find_matching_asset(latest_release['assets'], os_identifiers, arch_identifiers)
		if not download_url:
			console.print('[dim red]Could not find a GitHub release matching distribution.[/]')
			return False

		# Download and unpack asset
		console.print(f'Found release URL: {download_url}')
		cls._download_and_unpack(download_url, CONFIG.dirs.bin, repo)
		return True

	@classmethod
	def get_latest_release(cls, github_handle):
		"""Get latest release from GitHub.

		Args:
			github_handle (str): A GitHub handle {user}/{repo}.

		Returns:
			dict: Latest release JSON from GitHub releases.
		"""
		if not github_handle:
			return False
		owner, repo = tuple(github_handle.split('/'))
		url = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
		headers = {}
		if CONFIG.cli.github_token:
			headers['Authorization'] = f'Bearer {CONFIG.cli.github_token}'
		try:
			response = requests.get(url, headers=headers, timeout=5)
			response.raise_for_status()
			latest_release = response.json()
			return latest_release
		except requests.RequestException as e:
			console.print(f'Failed to fetch latest release for {github_handle}: {str(e)}')
			return None

	@classmethod
	def get_latest_version(cls, github_handle):
		latest_release = cls.get_latest_release(github_handle)
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
			'x86_64': ['amd64', 'x86_64'],
			'amd64': ['amd64', 'x86_64'],
			'aarch64': ['arm64', 'aarch64'],
			'armv7l': ['armv7', 'arm'],
			'386': ['386', 'x86', 'i386'],
		}

		os_identifiers = os_mapping.get(system, [])
		arch_identifiers = arch_mapping.get(arch, [])
		return os_identifiers, arch_identifiers

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
		"""Download and unpack a release asset."""
		console.print(f'Downloading and unpacking to {destination}...')
		response = requests.get(url, timeout=5)
		response.raise_for_status()

		# Create a temporary directory to extract the archive
		temp_dir = os.path.join("/tmp", repo_name)
		os.makedirs(temp_dir, exist_ok=True)

		if url.endswith('.zip'):
			with zipfile.ZipFile(io.BytesIO(response.content)) as zip_ref:
				zip_ref.extractall(temp_dir)
		elif url.endswith('.tar.gz'):
			with tarfile.open(fileobj=io.BytesIO(response.content), mode='r:gz') as tar:
				tar.extractall(path=temp_dir)

		# For archives, find and move the binary that matches the repo name
		binary_path = cls._find_binary_in_directory(temp_dir, repo_name)
		if binary_path:
			os.chmod(binary_path, 0o755)  # Make it executable
			shutil.move(binary_path, os.path.join(destination, repo_name))  # Move the binary
		else:
			console.print('[bold red]Binary matching the repository name was not found in the archive.[/]')

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
		str: Version string.
	"""
	from secator.runners import Command
	import re
	regex = r'[0-9]+\.[0-9]+\.?[0-9]*\.?[a-zA-Z]*'
	ret = Command.execute(version_cmd, quiet=True, print_errors=False)
	match = re.findall(regex, ret.output)
	if not match:
		return ''
	return match[0]


def get_version_info(name, version_flag=None, github_handle=None, version=None):
	"""Get version info for a command.

	Args:
		name (str): Command name.
		version_flag (str): Version flag.
		github_handle (str): Github handle.
		version (str): Existing version.

	Return:
		dict: Version info.
	"""
	from packaging import version as _version
	from secator.installer import GithubInstaller
	info = {
		'name': name,
		'installed': False,
		'version': version,
		'latest_version': None,
		'location': None,
		'status': ''
	}

	# Get binary path
	location = which(name).output
	info['location'] = location

	# Get current version
	if version_flag:
		version_cmd = f'{name} {version_flag}'
		version = get_version(version_cmd)
		info['version'] = version

	# Get latest version
	latest_version = None
	if not CONFIG.offline_mode:
		latest_version = GithubInstaller.get_latest_version(github_handle)
		info['latest_version'] = latest_version

	if location:
		info['installed'] = True
		if version and latest_version:
			if _version.parse(version) < _version.parse(latest_version):
				info['status'] = 'outdated'
			else:
				info['status'] = 'latest'
		elif not version:
			info['status'] = 'current unknown'
		elif not latest_version:
			info['status'] = 'latest unknown'
			if CONFIG.offline_mode:
				info['status'] += ' [dim orange1]\[offline][/]'
	else:
		info['status'] = 'missing'

	return info


def fmt_health_table_row(version_info, category=None):
	name = version_info['name']
	version = version_info['version']
	status = version_info['status']
	installed = version_info['installed']
	name_str = f'[magenta]{name:<13}[/]'

	# Format version row
	_version = version or ''
	_version = f'[bold green]{_version:<10}[/]'
	if status == 'latest':
		_version += ' [bold green](latest)[/]'
	elif status == 'outdated':
		_version += ' [bold red](outdated)[/]'
	elif status == 'missing':
		_version = '[bold red]missing[/]'
	elif status == 'ok':
		_version = '[bold green]ok        [/]'
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
