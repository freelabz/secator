"""Celery events driver: publish a Celery task when a top-level run ends.

Lets a deployment start post-run processing (duplicate tagging, summaries, notifications...)
as soon as a run finishes, instead of polling the store for recently ended runs.

The driver only reads the runner's own state, so it behaves the same next to any store driver
(json, sqlite, mongodb, api). It is a no-op until ``addons.celery_events.run_end_task`` names
the task to publish, e.g.:

	SECATOR_ADDONS_CELERY_EVENTS_RUN_END_TASK=myapp.tasks.on_run_end
	SECATOR_ADDONS_CELERY_EVENTS_QUEUE=post-run   # optional, default routing otherwise

The task receives keyword arguments only: ``runner_type``, ``runner_id``, ``runner_chunk_id``,
``name``, ``status``, ``workspace_id`` and ``end_time`` (ISO 8601). ``runner_chunk_id`` is the
run's ``{type}_chunk_id`` when it has one (the command run of a task the ``ai`` task spawned): the
mongodb store keys that run's doc on it, the api store on ``runner_id``, so look the run up by
``runner_chunk_id`` first and fall back to ``runner_id``. Delivery is best effort: the run has
already finished, so a broker error is logged at debug level and never fails or alters the run.
"""
from secator.config import CONFIG
from secator.runners import Scan, Task, Workflow
from secator.utils import debug

# Post phase: run after the persistence drivers, so the published run is already stored with its
# final status when a consumer reads it.
HOOK_PHASE = 'post'

# Bounded publish retries: the hook runs on the worker that just finished the run, so a broker
# outage must not stall it for long.
PUBLISH_RETRY_POLICY = {'max_retries': 3, 'interval_start': 0, 'interval_step': 1, 'interval_max': 2}


def run_end_payload(runner):
	"""Small, id-only description of a finished top-level run (no targets, no results)."""
	runner_type = runner.config.type
	return {
		'runner_type': runner_type,
		'runner_id': runner.context.get(f'{runner_type}_id'),
		# A task spawned by the `ai` task carries its own chunk id. The mongodb store keys its doc on
		# it (`task_id` is never stored there), the api store on `task_id`: send both.
		'runner_chunk_id': runner.context.get(f'{runner_type}_chunk_id'),
		'name': runner.config.name,
		'status': runner.status,
		'workspace_id': runner.context.get('workspace_id'),
		'end_time': runner.end_time.isoformat() if runner.end_time else None,
	}


def publish_run_end(self):
	"""on_run_end hook: send the configured Celery task for this finished run."""
	task_name = CONFIG.addons.celery_events.run_end_task
	if not task_name:
		return
	try:
		from secator.celery import app
		payload = run_end_payload(self)
		app.send_task(
			task_name,
			kwargs=payload,
			queue=CONFIG.addons.celery_events.queue or None,
			retry=True,
			retry_policy=PUBLISH_RETRY_POLICY,
		)
		debug(f'published {task_name}', sub='hooks.celery_events', obj=payload)
	except Exception as e:
		debug(f'could not publish {task_name}: {e}', sub='hooks.celery_events')


HOOKS = {
	Scan: {'on_run_end': [publish_run_end]},
	Workflow: {'on_run_end': [publish_run_end]},
	Task: {'on_run_end': [publish_run_end]},
}
