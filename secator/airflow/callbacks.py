"""Airflow callbacks for secator lifecycle events.

Replaces secator's hook system (``on_init``, ``on_start``, ``on_item``,
``on_end``, ``on_duplicate``) with Airflow-native callbacks that are wired to
operators via ``on_success_callback``, ``on_failure_callback``, and DAG-level
``on_success_callback``.

These callbacks handle:
    - Persisting individual findings to MongoDB
    - Updating runner (task/workflow/scan) state in MongoDB
    - Triggering duplicate detection at the end of a scan
"""

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def _get_mongodb_db():
    """Get the MongoDB database handle, or None if MongoDB is disabled."""
    from secator.config import CONFIG
    if not CONFIG.addons.mongodb.enabled:
        return None
    from secator.hooks.mongodb import get_mongodb_client
    return get_mongodb_client().main


def on_task_success(context):
    """Called when a SecatorTaskOperator succeeds.

    Persists all findings to MongoDB and updates the runner record.

    Args:
        context: Airflow callback context dict.
    """
    db = _get_mongodb_db()
    if db is None:
        return

    ti = context['task_instance']
    dag_run = context['dag_run']

    # Persist findings
    results = ti.xcom_pull(key='results') or []
    for result in results:
        if isinstance(result, dict) and '_type' in result:
            _upsert_finding(db, result)

    # Update runner record
    _upsert_runner_record(db, ti, dag_run, 'SUCCESS')


def on_task_failure(context):
    """Called when a SecatorTaskOperator fails.

    Updates the runner record in MongoDB with failure status.

    Args:
        context: Airflow callback context dict.
    """
    db = _get_mongodb_db()
    if db is None:
        return

    ti = context['task_instance']
    dag_run = context['dag_run']
    _upsert_runner_record(db, ti, dag_run, 'FAILURE')


def on_dag_success(context):
    """Called when the entire DAG (workflow or scan) succeeds.

    Triggers workspace-level duplicate detection.

    Args:
        context: Airflow callback context dict.
    """
    db = _get_mongodb_db()
    if db is None:
        return

    dag_run = context['dag_run']
    workspace_id = dag_run.conf.get('workspace', 'default')
    dag_id = dag_run.dag_id

    logger.info("DAG %s completed, triggering duplicate detection for workspace %s", dag_id, workspace_id)

    # Trigger async deduplication
    try:
        from secator.hooks.mongodb import tag_duplicates
        tag_duplicates(workspace_id)
    except Exception:
        logger.exception("Duplicate detection failed for workspace %s", workspace_id)


def on_dag_failure(context):
    """Called when a DAG fails.

    Args:
        context: Airflow callback context dict.
    """
    dag_run = context['dag_run']
    logger.error("DAG %s failed (run_id=%s)", dag_run.dag_id, dag_run.run_id)


# ---------------------------------------------------------------------------
# MongoDB persistence helpers
# ---------------------------------------------------------------------------


def _upsert_finding(db, finding_dict):
    """Insert or update a finding in MongoDB.

    Args:
        db: PyMongo database handle.
        finding_dict (dict): Serialized OutputType dict.
    """
    from bson.objectid import ObjectId

    uuid = finding_dict.get('_uuid')
    try:
        if uuid and ObjectId.is_valid(uuid):
            db.findings.update_one(
                {'_id': ObjectId(uuid)},
                {'$set': finding_dict},
                upsert=True,
            )
        else:
            result = db.findings.insert_one(finding_dict)
            finding_dict['_uuid'] = str(result.inserted_id)
    except Exception:
        logger.exception("Failed to upsert finding")


def _upsert_runner_record(db, ti, dag_run, status):
    """Insert or update a runner (task) record in MongoDB.

    Mirrors ``secator/hooks/mongodb.py::update_runner()`` but adapted for
    Airflow's TaskInstance model.

    Args:
        db: PyMongo database handle.
        ti: Airflow TaskInstance.
        dag_run: Airflow DagRun.
        status (str): Final status string (SUCCESS, FAILURE, etc.).
    """
    record = {
        'name': ti.task_id,
        'status': status,
        'dag_id': dag_run.dag_id,
        'run_id': dag_run.run_id,
        'start_time': ti.start_date.isoformat() if ti.start_date else None,
        'end_time': ti.end_date.isoformat() if ti.end_date else None,
        'duration': ti.duration,
        'try_number': ti.try_number,
        'workspace': dag_run.conf.get('workspace', 'default'),
        'updated_at': datetime.now(timezone.utc).isoformat(),
    }

    try:
        # Use dag_run_id + task_id as the unique key
        db.tasks.update_one(
            {'dag_run_id': dag_run.run_id, 'task_id': ti.task_id},
            {'$set': record},
            upsert=True,
        )
    except Exception:
        logger.exception("Failed to upsert runner record for %s", ti.task_id)
