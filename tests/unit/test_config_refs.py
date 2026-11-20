"""Every `CONFIG.a.b.c` attribute chain in the package must resolve to a real config key.

`CONFIG` is a DotMap: reading a key that does not exist returns an empty, falsy DotMap instead
of raising, so a typo or a wrong section silently disables the setting it was meant to read.
This test walks the AST of every module and checks each chain against the pydantic schema.
"""
import ast
import typing
import unittest
from pathlib import Path

from pydantic import BaseModel

import secator
from secator.config import Config, SecatorConfig

PACKAGE_DIR = Path(secator.__file__).parent

# Methods / private attributes of the DotMap-based Config wrapper (CONFIG.validate(), CONFIG._path,
# CONFIG.addons.mongodb.toDict(), ...): they are not schema keys.
CONFIG_ATTRIBUTES = {name for name in dir(Config)} | {'_path', '_error', '_partial'}


def _model_of(annotation):
	"""Return the pydantic model class of a field annotation, or None if it is not a model."""
	if isinstance(annotation, type) and issubclass(annotation, BaseModel):
		return annotation
	for arg in typing.get_args(annotation):  # Optional[Model] / Union[Model, ...]
		if isinstance(arg, type) and issubclass(arg, BaseModel):
			return arg
	return None


def _config_chains(tree):
	"""Yield (lineno, [attr, ...]) for every outermost `CONFIG.x.y...` attribute chain."""
	inner = set()
	for node in ast.walk(tree):
		if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Attribute):
			inner.add(id(node.value))
	for node in ast.walk(tree):
		if not isinstance(node, ast.Attribute) or id(node) in inner:
			continue
		parts = []
		cur = node
		while isinstance(cur, ast.Attribute):
			parts.append(cur.attr)
			cur = cur.value
		if isinstance(cur, ast.Name) and cur.id == 'CONFIG':
			yield node.lineno, list(reversed(parts))


def _missing_key(parts):
	"""Return the first attribute of `parts` that is not a schema key, or None if it resolves."""
	model = SecatorConfig
	for part in parts:
		if model is None:
			return None  # past a leaf (str, dict, list): anything goes from here
		if part in model.model_fields:
			model = _model_of(model.model_fields[part].annotation)
			continue
		if part in CONFIG_ATTRIBUTES:
			return None
		return part
	return None


class TestConfigReferences(unittest.TestCase):

	def test_all_config_attribute_chains_exist_in_schema(self):
		errors = []
		for path in sorted(PACKAGE_DIR.rglob('*.py')):
			tree = ast.parse(path.read_text(), filename=str(path))
			for lineno, parts in _config_chains(tree):
				missing = _missing_key(parts)
				if missing:
					rel = path.relative_to(PACKAGE_DIR.parent)
					errors.append(f'{rel}:{lineno}: CONFIG.{".".join(parts)} (unknown key "{missing}")')
		self.assertEqual(errors, [], 'CONFIG reads of keys missing from the config schema:\n' + '\n'.join(errors))

	def test_checker_flags_unknown_keys(self):
		self.assertEqual(_missing_key(['cli', 'worker_command_verbose']), 'worker_command_verbose')
		self.assertEqual(_missing_key(['runners', 'nope']), 'nope')
		self.assertIsNone(_missing_key(['celery', 'worker_command_verbose']))
		self.assertIsNone(_missing_key(['addons', 'mongodb', 'toDict']))
		self.assertIsNone(_missing_key(['validate']))
