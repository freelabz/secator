"""Tests for issue #1287: when multiple invalid targets are passed, ALL must be ignored.

Root cause was a mutate-while-iterate bug in Runner._validate_inputs: it iterated over
`self.inputs` while calling `self.inputs.remove(...)`, so removing an element shifted the
iterator and skipped the following (also-invalid) target.
"""
import unittest

from secator.decorators import task
from secator.definitions import URL
from secator.output_types import Info
from secator.runners import PythonRunner


@task()
class UrlOnlyTask(PythonRunner):
    """Only accepts URL inputs; host:port targets must be rejected."""
    input_types = [URL]
    output_types = [Info]

    def yielder(self):
        for inp in self.inputs:
            yield Info(message=f"Processing {inp}")


class TestMultipleInvalidTargets(unittest.TestCase):

    def test_two_invalid_targets_both_ignored(self):
        """Both host:port targets are invalid for a URL-only task and must both be dropped."""
        runner = UrlOnlyTask(inputs=['localhost:8085', 'localhost:1090'])
        self.assertEqual(
            runner.inputs, [],
            f"Both invalid targets should be ignored, got leftover: {runner.inputs}"
        )


if __name__ == '__main__':
    unittest.main()
