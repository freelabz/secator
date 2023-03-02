import operator

import yaml
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

from secsy.definitions import RECORD

console = Console(stderr=True, record=RECORD)
console_stdout = Console(record=True)
handler = RichHandler(rich_tracebacks=True)


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

formatters = {
	'confidence': criticity_to_color,
	'severity': criticity_to_color,
	'cvss_score': lambda score: '' if score == -1 else f'[bold blue]{score}[/]',
	'port': lambda port: f'[bold blue]{port}[/]'
}

def build_table(items, output_fields=[], sort_by=None):
	"""Build rich table.

	Args:
		items (list): List of items.
		output_fields (list, Optional): List of fields to add.
		sort_by (tuple, Optional): Tuple of sort_by keys.

	Returns:
		rich.table.Table: rich table.
	"""

	# Sort items by one or multiple fields
	if sort_by and all(sort_by):
		items = sorted(items, key=operator.itemgetter(*sort_by))

	# Create rich table
	table = Table(show_lines=True)

	# Get table schema if any, default to first item keys
	cls = items[0].get('_cls')
	if output_fields:
		keys = output_fields
	elif cls and cls.output_table_fields:
		keys = cls.output_table_fields
	else:
		keys = list(items[0].keys())

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
		no_wrap = key in ['url', 'references', 'matched_at']
		overflow = None if no_wrap else 'fold'
		table.add_column(
			key_str,
			overflow=overflow,
			no_wrap=no_wrap,
			header_style='bold blue')

	# Create table rows
	for item in items:
		values = []
		for key in keys:
			value = item[key]
			value = formatters.get(key, lambda x: x)(value)
			if isinstance(value, dict) or isinstance(value, list):
				value = yaml.dump(value)
			elif isinstance(value, int) or isinstance(value, float):
				value = str(value)
			values.append(value)
		table.add_row(*values)
	return table