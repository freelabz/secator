"""A `_uuid` that is an ObjectId string seeks the native `_id` (index) instead of
scanning the `_uuid` field; a uuid4 (json/sqlite / pre-backfill) stays a field match."""
import unittest
import uuid

import pytest


class TestSeekByNativeId(unittest.TestCase):
    def setUp(self):
        pytest.importorskip("pymongo")
        from secator.query.mongodb import _seek_by_native_id
        self.seek = _seek_by_native_id

    def test_objectid_uuid_rewritten_to_id(self):
        from bson.objectid import ObjectId
        oid = str(ObjectId())
        q = self.seek({'_type': 'vulnerability', '_uuid': oid})
        self.assertNotIn('_uuid', q)
        self.assertEqual(q['_id'], ObjectId(oid))
        self.assertEqual(q['_type'], 'vulnerability')  # other conditions preserved

    def test_uuid4_left_as_field_match(self):
        u = str(uuid.uuid4())  # not a valid ObjectId
        q = self.seek({'_uuid': u})
        self.assertEqual(q['_uuid'], u)
        self.assertNotIn('_id', q)

    def test_operator_dict_untouched(self):
        q = self.seek({'_uuid': {'$in': ['a', 'b']}})
        self.assertEqual(q['_uuid'], {'$in': ['a', 'b']})
        self.assertNotIn('_id', q)


class TestUpdateScopeOnly(unittest.TestCase):
    """Idempotency: a targeted update is scoped by workspace only — the `is_false_positive`
    DISPLAY filter must not gate writes, else re-marking an already-FP finding matches 0 rows."""

    def _backend(self):
        pytest.importorskip("pymongo")
        from secator.query.mongodb import MongoDBBackend
        return MongoDBBackend("ws1")  # no client needed for _merge_query

    def test_reads_keep_display_filter_writes_drop_it(self):
        b = self._backend()
        read = b._merge_query({'_uuid': 'x'})
        self.assertIn('is_false_positive', read)                     # reads hide FPs
        self.assertEqual(read['_context.workspace_id'], 'ws1')
        write = b._merge_query({'_uuid': 'x'}, scope_only=True)
        self.assertNotIn('is_false_positive', write)                 # writes reach FP findings
        self.assertNotIn('_tagged', write)
        self.assertEqual(write['_context.workspace_id'], 'ws1')      # scope still enforced

    def test_update_passes_scope_only(self):
        from unittest.mock import patch
        b = self._backend()
        with patch.object(b, '_execute_update', return_value=1) as ex:
            b.update({'_uuid': 'x'}, {'$set': {'a': 1}})
        q = ex.call_args[0][0]
        self.assertNotIn('is_false_positive', q)
        self.assertEqual(q['_context.workspace_id'], 'ws1')


class TestSqliteUuidColumn(unittest.TestCase):
    def test_uuid_maps_to_pk_column(self):
        from secator.query.sqlite import _col_expr
        self.assertEqual(_col_expr('_uuid'), 'uuid')  # indexed PK, not json_extract
        self.assertIn('json_extract', _col_expr('name'))  # unmirrored field still scans


if __name__ == "__main__":
    unittest.main()
