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
    def _child_descriptions(self, run_opts):
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
                run_opts=run_opts,
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

    def _scan_child_workflow_opts(self, config_options):
        """Return each child workflow's resolved run_opts. The scan-level description
        would land on the child workflow (its own card / run_opts), which the
        workflow-level task guard alone would not stop — so spy on the child workflows
        Scan builds, not the persisted task docs."""
        import secator.hooks.mongodb as m
        import secator.runners.scan as scan_mod
        from dotmap import DotMap
        from secator.runners.scan import Scan
        from secator.template import TemplateLoader

        sink = []
        captured = []
        RealWorkflow = scan_mod.Workflow

        def _spy(config, inputs, run_opts=None, **kw):
            captured.append(dict(run_opts or {}))
            return RealWorkflow(config, inputs, run_opts=run_opts, **kw)

        orig_client = m.get_mongodb_client
        m.get_mongodb_client = lambda: _FakeClient(sink)
        scan_mod.Workflow = _spy
        try:
            cfg = TemplateLoader(name="scan/host")
            scan = Scan(
                cfg,
                inputs=["1.2.3.4"],
                hooks=m.HOOKS,
                run_opts={},
                context={"workspace_id": "ws1", "drivers": ["mongodb"]},
            )
            # self.config.options is the runner's resolved value dict (what scan.py reads
            # as scan_opts) — inject the scan-level description there.
            scan.config.options = DotMap(config_options)
            scan.build_celery_workflow()
        finally:
            m.get_mongodb_client = orig_client
            scan_mod.Workflow = RealWorkflow
        return captured

    def test_child_tasks_keep_their_own_description(self):
        descs = self._child_descriptions({"description": "AI WORKFLOW DESC"})
        self.assertTrue(descs, "expected child task docs to be built")
        # The workflow description must not have leaked onto any child.
        self.assertNotIn("AI WORKFLOW DESC", set(descs.values()))
        # And each task keeps its own YAML description.
        self.assertEqual(descs.get("nmap"), "Detect services and versions")
        self.assertEqual(descs.get("sshaudit"), "Audit SSH port")

    def test_workflow_prefixed_description_not_cascaded(self):
        # A `<workflow_name>_description` run-opt is normalized to `description` by the
        # prefix loop; it must still be dropped before tasks are built.
        descs = self._child_descriptions({"host_recon_description": "PREFIXED DESC"})
        self.assertTrue(descs, "expected child task docs to be built")
        self.assertNotIn("PREFIXED DESC", set(descs.values()))
        self.assertEqual(descs.get("nmap"), "Detect services and versions")

    def test_scan_config_description_not_cascaded(self):
        # A description in the SCAN config options must not cascade to its child workflows.
        opts = self._scan_child_workflow_opts({"description": "SCAN DESC"})
        self.assertTrue(opts, "expected child workflows to be built")
        self.assertNotIn("SCAN DESC", [o.get("description") for o in opts])


if __name__ == "__main__":
    unittest.main()
