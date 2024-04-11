
import requests
import os
import platform
import shutil
import tarfile
import zipfile
import io

from threading import Thread

from secator.rich import console
from secator.runners import Command
from secator.definitions import BIN_FOLDER, GITHUB_TOKEN


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
		cls._download_and_unpack(download_url, BIN_FOLDER, repo)
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
		if GITHUB_TOKEN:
			headers['Authorization'] = f'Bearer {GITHUB_TOKEN}'
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

def fetch_tool_releases(tools):
	"""Fetch the latest releases for a list of tools using threading.

	Args:
		tools (list): List of tool classes.

	Returns:
		dict: {tool_cls: latest_version}
	"""
	threads = []
	results = {}

	def fetch_and_store(tool):
		"""Helper function to fetch data and store it in results."""
		latest_version = GithubInstaller.get_latest_version(tool.install_github_handle)
		results[tool] = latest_version

	for tool in tools:
		thread = Thread(target=fetch_and_store, args=(tool,))
		thread.start()
		threads.append(thread)

	# Wait for all threads to complete
	for thread in threads:
		thread.join()

	return results


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


def get_version_info(name, version_flag=None, github_handle=None):
	"""Get version info for a command.

	Args:
		name (str): Command name.
		version_flag (str): Version flag.
		github_handle (str): Github handle.

	Return:
		dict: Version info.
	"""
	from pkg_resources import parse_version
	from secator.installer import GithubInstaller
	version_info = {
		'name': name,
		'installed': False,
		'version': None,
		'latest_version': None,
		'location': None,
		'status': 'missing'
	}

	# Get binary path
	location = which(name).output
	version_info['location'] = location
	if location:
		version_info['installed'] = True
		version_info['status'] = 'outdated'

	# Get current version
	if not version_flag:
		return version_info
	version_cmd = f'{name} {version_flag}'
	version = get_version(version_cmd)
	version_info['version'] = version

	# Get latest version
	if not github_handle:
		return version_info
	latest_version = GithubInstaller.get_latest_version(github_handle)
	version_info['latest_version'] = latest_version

	if not version and not latest_version:
		version_info['status'] = 'unknown'
	
	elif not latest_version:
		version_info['status'] = 'ok'
	
	elif not version:
		version_info['status'] = 'missing'
	
	elif parse_version(version)< parse_version(latest_version):
		version_info['status'] = 'outdated'
	
	else:
		version_info['status'] = 'ok'

	return version_info


def print_version_info(version_info, category=None):
	name = version_info['name']
	version = version_info['version']
	location = version_info['location']
	latest_version = version_info['latest_version']
	status = version_info['status']
	if status == 'outdated':
		status_color = 'bold orange1'
	elif status == 'ok':
		status_color = 'bold green'
	elif status == 'missing':
		status_color = 'bold red'
	else:
		status_color = 'bold turquoise4'
	s = f'[bold magenta]{name:<15}[/] [{status_color}]{status:<12}[/]'
	if version:
		if version == 'N/A':
			version_color = 'dim blue'
		elif status == 'outdated':
			version_color = 'bold orange1'
			version += f' [dim](<{latest_version})[/] '
		else:
			version_color = 'bold green'
		s += f'[{version_color}]{version:<15}[/]'
	else:
		s += ' '*15
	if location:
		s += f'[dim gold3]{location}[/]'
	elif category:
		s += f'[dim]# secator install {category} {name}'
	console.print(s, highlight=False)