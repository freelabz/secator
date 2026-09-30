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


class TestSqliteUuidColumn(unittest.TestCase):
    def test_uuid_maps_to_pk_column(self):
        from secator.query.sqlite import _col_expr
        self.assertEqual(_col_expr('_uuid'), 'uuid')  # indexed PK, not json_extract
        self.assertIn('json_extract', _col_expr('name'))  # unmirrored field still scans


if __name__ == "__main__":
    unittest.main()
