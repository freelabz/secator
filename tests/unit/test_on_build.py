import unittest


class TestOnBuildHookRegistration(unittest.TestCase):
    def test_on_build_is_a_valid_hook_name(self):
        from secator.runners._base import HOOKS
        assert 'on_build' in HOOKS
