"""Regression test for the GCS hook: it must preserve the blob-naming id in
`_context.blob_uuid` so blob ownership can be checked against a server-owned handle
even after a DB backend rewrites `_uuid` to its native id."""
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import pytest

# The gcs addon (google-cloud-storage) is an optional extra; skip cleanly when absent
# (importing secator.hooks.gcs pulls it).
pytest.importorskip("google.cloud.storage")

from secator.hooks import gcs  # noqa: E402
from secator.output_types import Url  # noqa: E402


class _FakeRunner:
    def __init__(self):
        self.threads = []


@unittest.skipUnless(True, "gcs addon")
class TestGcsBlobUuid(unittest.TestCase):
    def test_stamps_blob_uuid_and_rewrites_path(self):
        with tempfile.NamedTemporaryFile(suffix=".png") as f:
            item = Url(url="http://x/", screenshot_path=f.name)
            item._uuid = "the-upload-id"  # what runner-core stamps before any DB flip
            with patch.object(gcs, "GCS_BUCKET_NAME", "bkt"), \
                 patch.object(gcs, "Thread", MagicMock()):
                out = gcs.process_item(_FakeRunner(), item)
        # the blob-naming id is preserved in _context, decoupled from _uuid
        self.assertEqual(out._context["blob_uuid"], "the-upload-id")
        # the path was rewritten to the gs:// url named by that id
        self.assertEqual(out.screenshot_path, "gs://bkt/the-upload-id_screenshot_path.png")

    def test_no_blob_uuid_when_nothing_uploaded(self):
        # a url with no on-disk path fields -> no blob, no _context.blob_uuid stamped
        item = Url(url="http://x/")
        with patch.object(gcs, "GCS_BUCKET_NAME", "bkt"), \
             patch.object(gcs, "Thread", MagicMock()):
            out = gcs.process_item(_FakeRunner(), item)
        self.assertNotIn("blob_uuid", out._context)


if __name__ == "__main__":
    unittest.main()
