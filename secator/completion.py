"""Shell completion functions for secator CLI."""

import os
from click.shell_completion import CompletionItem

from secator.config import CONFIG
from secator.loader import get_configs_by_type, get_available_drivers, get_available_exporters


def complete_profiles(ctx, param, incomplete):
	"""Complete profile names."""
	profiles = get_configs_by_type('profile')
	profile_names = [p.name for p in profiles]
	return [
		CompletionItem(name)
		for name in profile_names
		if name.startswith(incomplete)
	]


def complete_workspaces(ctx, param, incomplete):
	"""Complete workspace names."""
	try:
		workspaces = next(os.walk(CONFIG.dirs.reports))[1]
	except (StopIteration, OSError):
		workspaces = []
	return [
		CompletionItem(name)
		for name in workspaces
		if name.startswith(incomplete)
	]


def complete_drivers(ctx, param, incomplete):
	"""Complete driver names."""
	return [
		CompletionItem(name)
		for name in get_available_drivers()
		if name.startswith(incomplete)
	]


def complete_exporters(ctx, param, incomplete):
	"""Complete exporter names."""
	return [
		CompletionItem(name)
		for name in get_available_exporters()
		if name.startswith(incomplete)
	]
