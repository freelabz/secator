import operator

import yaml
from rich import box
from rich.console import Console
from rich.table import Table

console = Console(stderr=True, color_system='truecolor')
console_stdout = Console(record=True)
# handler = RichHandler(rich_tracebacks=True)  # TODO: add logging handler


def criticity_to_color(value):
	if value == 'critical':
		value = f'[bold red3]{value.upper()}[/]'
	elif value == 'high':
		value = f'[bold orange_red1]{value.upper()}[/]'
	elif value == 'medium':
		value = f'[bold dark_orange]{value.upper()}[/]'
	elif value == 'low':
		value = f'[bold yellow1]{value.upper()}[/]'
	elif value == 'info':
		value = f'[bold green]{value.upper()}[/]'
	return value


def status_to_color(value):
	value = int(value) if value else None
	if value is None:
		return value
	if value < 400:
		value = f'[bold green]{value}[/]'
	elif value in [400, 499]:
		value = f'[bold dark_orange]{value}[/]'
	elif value >= 500:
		value = f'[bold red3]{value}[/]'
	return value


FORMATTERS = {
	'confidence': criticity_to_color,
	'severity': criticity_to_color,
	'cvss_score': lambda score: '' if score == -1 else f'[bold cyan]{score}[/]',
	'port': lambda port: f'[bold cyan]{port}[/]',
	'url': lambda host: f'[bold underline blue]{host}[/]',
	'ip': lambda ip: f'[bold yellow]{ip}[/]',
	'status_code': status_to_color,
	'reference': lambda reference: f'[link={reference}]🡕[/]',
	'_source': lambda source: f'[bold gold3]{source}[/]'
}


def build_table(items, output_fields=[], exclude_fields=[], sort_by=None):
	"""Build rich table.

	Args:
		items (list): List of items.
		output_fields (list, Optional): List of fields to add.
		exclude_fields (list, Optional): List of fields to exclude.
		sort_by (tuple, Optional): Tuple of sort_by keys.

	Returns:
		rich.table.Table: rich table.
	"""
	# Sort items by one or multiple fields
	if sort_by and all(sort_by):
		items = sorted(items, key=operator.attrgetter(*sort_by))

	# Create rich table
	box_style = box.ROUNDED
	table = Table(show_lines=True, box=box_style)

	# Get table schema if any, default to first item keys
	keys = output_fields

	# List of fields to exclude
	keys = [k for k in keys if k not in exclude_fields]

	# Remove meta fields not needed in output
	if '_cls' in keys:
		keys.remove('_cls')
	if '_type' in keys:
		keys.remove('_type')
	if '_uuid' in keys:
		keys.remove('_uuid')

	# Add _source field
	if '_source' not in keys:
		keys.append('_source')

	# Create table columns
	for key in keys:
		key_str = key
		if not key.startswith('_'):
			key_str = ' '.join(key.split('_')).upper()
		no_wrap = key in ['url', 'reference', 'references', 'matched_at']
		overflow = None if no_wrap else 'fold'
		table.add_column(
			key_str,
			overflow=overflow,
			min_width=10,
			no_wrap=no_wrap,
			header_style='bold blue')

	# Create table rows
	for item in items:
		values = []
		for key in keys:
			value = getattr(item, key)
			value = FORMATTERS.get(key, lambda x: x)(value)
			if isinstance(value, dict) or isinstance(value, list):
				value = yaml.dump(value)
			elif isinstance(value, int) or isinstance(value, float):
				value = str(value)
			values.append(value)
		table.add_row(*values)
	return table
