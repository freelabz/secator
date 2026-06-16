"""Regression tests for the MongoDB driver hooks.

A runner whose state (or a single finding) exceeds MongoDB's 16MB BSON limit used
to raise `pymongo.errors.DocumentTooLarge` straight through `run_hooks`, crashing
the runner. The hooks must instead catch it, emit a Warning, and carry on.
"""
import unittest
from unittest.mock import MagicMock, patch

import pytest

# The mongodb addon (pymongo) is an optional extra and is NOT installed in the base
# unit-test environment (CI). Skip this whole module cleanly when it's absent —
# importing secator.hooks.mongodb also pulls pymongo, so guard before that import.
pymongo = pytest.importorskip("pymongo")

from secator.hooks import mongodb  # noqa: E402
from secator.output_types import Info, Warning  # noqa: E402


class _Cfg:
    type = "task"
    name = "nmap"


class _FakeRunner:
    def __init__(self):
        self.config = _Cfg()
        self.context = {"task_id": "0" * 24}
        self.unique_name = "nmap"
        self.status = "RUNNING"
        self.results = []
        self.last_updated_db = None

    def toDict(self):
        return {"status": "RUNNING"}

    def add_result(self, item, **kwargs):
        self.results.append(item)


def _client_raising_too_large():
    """A mongo client mock whose writes all raise DocumentTooLarge."""
    client = MagicMock()
    coll = client.main.__getitem__.return_value
    err = pymongo.errors.DocumentTooLarge("'update' command document too large")
    coll.update_one.side_effect = err
    coll.insert_one.side_effect = err
    return client


class TestMongoDocumentTooLarge(unittest.TestCase):
    def test_update_runner_warns_instead_of_raising(self):
        with patch.object(mongodb, "get_mongodb_client", return_value=_client_raising_too_large()):
            runner = _FakeRunner()
            mongodb.update_runner(runner)  # must not raise
        warnings = [r for r in runner.results if isinstance(r, Warning)]
        self.assertEqual(len(warnings), 1)
        self.assertIn("16MB", warnings[0].message)

    def test_update_finding_warns_and_returns_item(self):
        with patch.object(mongodb, "get_mongodb_client", return_value=_client_raising_too_large()):
            runner = _FakeRunner()
            item = Info(message="x")
            out = mongodb.update_finding(runner, item)  # must not raise
        self.assertIs(out, item)  # item returned so the chain continues
        warnings = [r for r in runner.results if isinstance(r, Warning)]
        self.assertEqual(len(warnings), 1)
        self.assertIn("16MB", warnings[0].message)


if __name__ == "__main__":
    unittest.main()
