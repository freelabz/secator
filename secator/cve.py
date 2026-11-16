import re
from typing import Optional, Tuple

from secator.utils import get_versions_from_string

SOFTWARE_NAME = r'([a-zA-Z][\w\s.+-]*?)'
VERSION_SIMPLE = re.compile(SOFTWARE_NAME + r'\s+([0-9]+\.[0-9]+(?:\.[0-9]+)*)')
VERSION_POSTFIX = re.compile(SOFTWARE_NAME + r'\s+([0-9]+\.[0-9]+(?:\.[0-9]+)*(?:[a-zA-Z][0-9])*)')


def extract_software_and_version(version_string: str, postfix=False) -> Tuple[Optional[str], Optional[str]]:
	"""Extract software name and version from a version string."""
	# Try to match software name followed by version
	regex = VERSION_POSTFIX if postfix else VERSION_SIMPLE
	match = regex.search(version_string.strip())
	if match:
		return match.group(1).strip().lower(), match.group(2).strip()

	# If no software name, try to extract just version
	versions = get_versions_from_string(version_string)
	return (None, versions[0]) if versions else (None, None)
