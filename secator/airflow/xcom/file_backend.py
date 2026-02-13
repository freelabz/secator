"""Custom XCom backend that stores large result sets as files on shared storage.

Secator tasks can produce thousands of findings per execution. The default Airflow
XCom backend stores data in the metadata database (PostgreSQL) with practical limits
around 48KB. This backend transparently offloads large lists to JSON files on a shared
filesystem (or S3/GCS with minor changes), keeping the metadata DB lean.

Configuration (airflow.cfg):
    [core]
    xcom_backend = secator.airflow.xcom.file_backend.FileXComBackend

Environment variables:
    SECATOR_XCOM_DIR  - directory for XCom overflow files (default: /tmp/secator_xcom)
    SECATOR_XCOM_THRESHOLD - min list length to trigger file offload (default: 50)
"""

import json
import logging
import os
import uuid as _uuid
from pathlib import Path

from airflow.models.xcom import BaseXCom

logger = logging.getLogger(__name__)

XCOM_RESULTS_DIR = os.environ.get('SECATOR_XCOM_DIR', '/tmp/secator_xcom')
XCOM_THRESHOLD = int(os.environ.get('SECATOR_XCOM_THRESHOLD', '50'))


class FileXComBackend(BaseXCom):
    """XCom backend that offloads large values to the filesystem.

    Small values (< XCOM_THRESHOLD items) are stored normally in the metadata DB.
    Large lists are serialized to JSON files and a reference path is stored in XCom.
    """

    @staticmethod
    def serialize_value(value, *, key=None, task_id=None, dag_id=None, run_id=None, map_index=None):
        # Only offload lists that exceed the threshold
        if isinstance(value, list) and len(value) > XCOM_THRESHOLD:
            file_id = _uuid.uuid4().hex[:12]
            filename = f"{dag_id}__{task_id}__{file_id}.json"
            dirpath = Path(XCOM_RESULTS_DIR)
            dirpath.mkdir(parents=True, exist_ok=True)
            filepath = dirpath / filename
            try:
                with open(filepath, 'w') as f:
                    json.dump(value, f, default=str)
                logger.info("XCom offloaded %d items to %s", len(value), filepath)
                return BaseXCom.serialize_value(f"__secator_file__{filepath}")
            except (OSError, TypeError) as e:
                logger.warning("XCom file offload failed (%s), falling back to DB", e)
        return BaseXCom.serialize_value(value)

    @staticmethod
    def deserialize_value(result):
        val = BaseXCom.deserialize_value(result)
        if isinstance(val, str) and val.startswith("__secator_file__"):
            filepath = val[len("__secator_file__"):]
            try:
                with open(filepath, 'r') as f:
                    return json.load(f)
            except (OSError, json.JSONDecodeError) as e:
                logger.error("Failed to read XCom file %s: %s", filepath, e)
                return []
        return val
