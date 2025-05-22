from collections import OrderedDict

import rich_click as click
from rich_click.rich_click import _get_rich_console
from rich_click.rich_group import RichGroup


class ListParamType(click.ParamType):
	"""Custom click param type to convert comma-separated strings to lists."""
	name = "list"

	def convert(self, value, param, ctx):
		if value is None:
			return []
		if isinstance(value, list):
			return value
		return [v.strip() for v in value.split(',') if v.strip()]


CLICK_LIST = ListParamType()


class OrderedGroup(RichGroup):
	def __init__(self, name=None, commands=None, **attrs):
		super(OrderedGroup, self).__init__(name, commands, **attrs)
		self.commands = commands or OrderedDict()

	def command(self, *args, **kwargs):
		"""Behaves the same as `click.Group.command()` but supports aliases.
		"""
		def decorator(f):
			aliases = kwargs.pop("aliases", None)
			if aliases:
				max_width = _get_rich_console().width
				aliases_str = ', '.join(f'[bold cyan]{alias}[/]' for alias in aliases)
				padding = max_width // 4

				name = kwargs.pop("name", None)
				if not name:
					raise click.UsageError("`name` command argument is required when using aliases.")

				f.__doc__ = f.__doc__ or '\0'.ljust(padding+1)
				f.__doc__ = f'{f.__doc__:<{padding}}[dim](aliases)[/] {aliases_str}'
				base_command = super(OrderedGroup, self).command(
					name, *args, **kwargs
				)(f)
				for alias in aliases:
					cmd = super(OrderedGroup, self).command(alias, *args, hidden=True, **kwargs)(f)
					cmd.help = f"Alias for '{name}'.\n\n{cmd.help}"
					cmd.params = base_command.params

			else:
				cmd = super(OrderedGroup, self).command(*args, **kwargs)(f)

			return cmd
		return decorator

	def group(self, *args, **kwargs):
		"""Behaves the same as `click.Group.group()` but supports aliases.
		"""
		def decorator(f):
			aliases = kwargs.pop('aliases', [])
			aliased_group = []
			if aliases:
				max_width = _get_rich_console().width
				aliases_str = ', '.join(f'[bold cyan]{alias}[/]' for alias in aliases)
				padding = max_width // 4
				f.__doc__ = f.__doc__ or '\0'.ljust(padding+1)
				f.__doc__ = f'{f.__doc__:<{padding}}[dim](aliases)[/] {aliases_str}'
				for alias in aliases:
					grp = super(OrderedGroup, self).group(
						alias, *args, hidden=True, **kwargs)(f)
					aliased_group.append(grp)

			# create the main group
			grp = super(OrderedGroup, self).group(*args, **kwargs)(f)
			grp.aliases = aliases

			# for all of the aliased groups, share the main group commands
			for aliased in aliased_group:
				aliased.commands = grp.commands

			return grp
		return decorator

	def list_commands(self, ctx):
		return self.commands
