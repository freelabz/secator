import pytest

from secator.tasks.bbot import bbot
from secator.tasks.wpprobe import wpprobe


class _Fake:
	def __init__(self, values):
		self.values = values

	def get_opt_value(self, key):
		return self.values.get(key)


def test_bbot_rejects_flag_injection_via_presets():
	with pytest.raises(ValueError):
		bbot.on_cmd(_Fake({'presets': 'web-basic,-c modules.x.exec=id'}))


def test_bbot_accepts_known_presets():
	assert bbot.on_cmd(_Fake({'presets': 'web-basic,spider'})) is None
	assert bbot.on_cmd(_Fake({'presets': None})) is None


def test_wpprobe_rejects_invalid_mode():
	with pytest.raises(ValueError):
		wpprobe.on_cmd(_Fake({'mode': 'scan; id'}))
