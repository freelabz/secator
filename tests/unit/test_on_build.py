import types
import unittest
from secator.hooks.mongodb import HOOKS as MONGO_HOOKS


class TestOnBuildHookRegistration(unittest.TestCase):
    def test_on_build_is_a_valid_hook_name(self):
        from secator.runners._base import HOOKS
        assert 'on_build' in HOOKS


class _FakeInsertResult:
    def __init__(self, _id):
        self.inserted_id = _id


class _FakeCollection:
    def __init__(self, name, sink):
        self.name = name
        self.sink = sink

    def insert_one(self, doc):
        _id = f'oid-{self.name}-{len(self.sink)}'
        self.sink.append((self.name, doc))
        return _FakeInsertResult(_id)

    def update_one(self, query, update):
        pass


class _FakeDB:
    def __init__(self, sink):
        self.sink = sink

    def __getitem__(self, name):
        return _FakeCollection(name, self.sink)


class _FakeClient:
    def __init__(self, sink):
        self.main = _FakeDB(sink)


def _patch_mongo(monkeypatch):
    sink = []
    import secator.hooks.mongodb as m
    monkeypatch.setattr(m, 'get_mongodb_client', lambda: _FakeClient(sink))
    return sink


class _FakeParent:
    """Minimal stand-in for a parent runner: on_build only reads .config.type."""
    def __init__(self, parent_type):
        self.config = types.SimpleNamespace(type=parent_type)


class TestOnBuildMongo:
    def test_workflow_parent_inserts_task_doc_and_stamps_task_id(self, monkeypatch):
        from secator.hooks.mongodb import on_build
        sink = _patch_mongo(monkeypatch)
        spec = {'name': 'httpx', 'context': {'workspace_id': 'ws1'}}
        on_build(_FakeParent('workflow'), spec)
        assert sink[0][0] == 'tasks'                       # inserted into tasks collection
        assert sink[0][1]['status'] == 'PENDING'
        assert spec['context']['task_id'] == 'oid-tasks-0' # stamped back into spec context

    def test_scan_parent_inserts_workflow_doc_and_stamps_workflow_id(self, monkeypatch):
        from secator.hooks.mongodb import on_build
        sink = _patch_mongo(monkeypatch)
        spec = {'name': 'url_fuzz', 'context': {'workspace_id': 'ws1'}}
        on_build(_FakeParent('scan'), spec)
        assert sink[0][0] == 'workflows'
        assert spec['context']['workflow_id'] == 'oid-workflows-0'

    def test_chunk_spec_stamps_task_chunk_id_and_chunk_flags(self, monkeypatch):
        from secator.hooks.mongodb import on_build
        sink = _patch_mongo(monkeypatch)
        spec = {'name': 'ffuf', 'chunk': 2, 'chunk_count': 5, 'context': {'workspace_id': 'ws1'}}
        on_build(_FakeParent('task'), spec)
        assert sink[0][0] == 'tasks'
        doc = sink[0][1]
        assert doc['has_parent'] is True
        assert doc['chunk'] == 2 and doc['chunk_count'] == 5
        assert spec['context']['task_chunk_id'] == 'oid-tasks-0'


class TestOnBuildWorkflowWiring(unittest.TestCase):
    def test_task_signatures_carry_task_id_from_on_build(self):
        from secator.runners.workflow import Workflow
        from secator.template import TemplateLoader
        sink = []

        import secator.hooks.mongodb as m
        orig = m.get_mongodb_client
        m.get_mongodb_client = lambda: _FakeClient(sink)
        try:
            config = TemplateLoader(name='workflow/host_recon')
            wf = Workflow(
                config,
                inputs=['example.com'],
                hooks=MONGO_HOOKS,
                context={'workspace_id': 'ws1', 'drivers': ['mongodb']},
            )
            wf.build_celery_workflow()
        finally:
            m.get_mongodb_client = orig

        # At least one task doc was inserted at build time...
        assert any(coll == 'tasks' for coll, _ in sink), \
            f'Expected tasks inserts but got: {[coll for coll, _ in sink]}'
        # ...and every tasks insert has status PENDING.
        assert all(doc['status'] == 'PENDING' for coll, doc in sink if coll == 'tasks')
