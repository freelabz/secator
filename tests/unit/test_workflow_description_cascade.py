"""A workflow/scan-level `description` must NOT cascade onto child tasks.

The AI's run_workflow/run_scan passes an LLM-supplied `description` run-opt; before
the fix it cascaded into every child's opts and overrode each task's own YAML
`description`, so every task carried the workflow description instead of its own
("Detect services and versions" / "Audit SSH port" / … in host_recon.yaml).
"""

import unittest

import pytest

from secator.definitions import ADDONS_ENABLED


class _FakeCollection:
    def __init__(self, name, sink):
        self.name = name
        self.sink = sink

    def insert_one(self, doc):
        self.sink.append((self.name, doc))

        class _R:
            inserted_id = "a" * 24

        return _R()

    def update_one(self, *a, **k):
        pass


class _FakeDB:
    def __init__(self, sink):
        self.sink = sink

    def __getitem__(self, name):
        return _FakeCollection(name, self.sink)


class _FakeClient:
    def __init__(self, sink):
        self.main = _FakeDB(sink)


@pytest.mark.skipif(
    not ADDONS_ENABLED["mongodb"], reason="mongodb addon (pymongo) not installed"
)
class TestWorkflowDescriptionCascade(unittest.TestCase):
    def _child_descriptions(self):
        import secator.hooks.mongodb as m
        from secator.runners.workflow import Workflow
        from secator.template import TemplateLoader

        sink = []
        orig = m.get_mongodb_client
        m.get_mongodb_client = lambda: _FakeClient(sink)
        try:
            cfg = TemplateLoader(name="workflow/host_recon")
            wf = Workflow(
                cfg,
                inputs=["1.2.3.4"],
                hooks=m.HOOKS,
                run_opts={"description": "AI WORKFLOW DESC"},
                context={"workspace_id": "ws1", "drivers": ["mongodb"]},
            )
            wf.build_celery_workflow()
        finally:
            m.get_mongodb_client = orig
        return {
            doc.get("name"): (doc.get("config") or {}).get("description", "")
            for coll, doc in sink
            if coll == "tasks"
        }

    def test_child_tasks_keep_their_own_description(self):
        descs = self._child_descriptions()
        self.assertTrue(descs, "expected child task docs to be built")
        # The workflow description must not have leaked onto any child.
        self.assertNotIn("AI WORKFLOW DESC", set(descs.values()))
        # And each task keeps its own YAML description.
        self.assertEqual(descs.get("nmap"), "Detect services and versions")
        self.assertEqual(descs.get("sshaudit"), "Audit SSH port")


if __name__ == "__main__":
    unittest.main()
