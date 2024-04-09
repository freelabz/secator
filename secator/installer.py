
import requests
import os
import platform
import shutil
import tarfile
import zipfile
import io

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
			bool: True if install is successful,, False otherwise.
		"""
		owner, repo = tuple(github_handle.split('/'))
		releases_url = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"

		# Query latest release endpoint
		headers = {}
		if GITHUB_TOKEN:
			headers['Authorization'] = f'Bearer {GITHUB_TOKEN}'
		response = requests.get(releases_url, headers=headers)
		if response.status_code == 403:
			console.print('[bold red]Rate-limited by GitHub API. Retry later or set a GITHUB_TOKEN.')
			return False
		elif response.status_code == 404:
			console.print('[dim red]No GitHub releases found.')
			return False

		# Find the right asset to download
		latest_release = response.json()
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
		response = requests.get(url)
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
