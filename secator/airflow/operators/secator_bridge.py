"""SecatorBridgeOperator - aggregates and deduplicates results from parallel tasks.

Replaces `secator/celery.py::forward_results()`. This operator sits after a
TaskGroup (parallel execution) and merges all upstream results into a single
deduplicated list, making them available to downstream tasks via XCom.

Usage in a DAG::

    with TaskGroup("crawl") as crawl_group:
        katana_task = SecatorTaskOperator(task_id='katana', ...)
        gospider_task = SecatorTaskOperator(task_id='gospider', ...)

    bridge = SecatorBridgeOperator(
        task_id='bridge_crawl',
    )

    crawl_group >> bridge >> next_task
"""

import logging

from airflow.models import BaseOperator

from secator.airflow.utils import deduplicate_results, flatten_results, get_finding_counts

logger = logging.getLogger(__name__)


class SecatorBridgeOperator(BaseOperator):
    """Aggregate and deduplicate results from upstream parallel tasks.

    This operator:
    1. Pulls ``results`` XCom from all upstream tasks
    2. Flattens nested result lists (from groups/mapped tasks)
    3. Deduplicates by ``_uuid``
    4. Pushes the merged list as ``results`` XCom for downstream tasks

    Args:
        pull_from_task_ids: Explicit list of upstream task_ids to pull from.
            If ``None``, auto-discovers all direct upstream relatives.
    """

    ui_color = '#87ceeb'
    ui_fgcolor = '#000000'

    def __init__(self, pull_from_task_ids=None, **kwargs):
        # Run even if some upstream tasks were skipped
        kwargs.setdefault('trigger_rule', 'none_failed_min_one_success')
        super().__init__(**kwargs)
        self._pull_from_task_ids = pull_from_task_ids

    def execute(self, context):
        ti = context['ti']
        all_results = []

        # Determine which upstream tasks to pull from.
        # Start with explicitly configured task IDs (group children), then
        # add any other direct upstream operators (previous bridges, standalone
        # tasks) so that results accumulate through the chain — mirroring
        # Celery's chain behavior where each step receives ALL prior results.
        task_ids = list(self._pull_from_task_ids or [])
        for op in self.get_direct_relatives(upstream=True):
            if op.task_id not in task_ids:
                task_ids.append(op.task_id)

        # Pull results from all upstream tasks
        for task_id in task_ids:
            pulled = ti.xcom_pull(task_ids=task_id, key='results')
            if pulled:
                if isinstance(pulled, list):
                    all_results.extend(pulled)
                else:
                    all_results.append(pulled)

        # Flatten nested lists (from mapped/grouped tasks)
        flat = flatten_results(all_results)

        # Deduplicate
        deduped = deduplicate_results(flat)

        # Log summary
        counts = get_finding_counts(deduped)
        counts_str = ", ".join(f"{k}: {v}" for k, v in counts.items()) if counts else "none"
        self.log.info(
            "Bridge: %d upstream tasks -> %d raw -> %d flat -> %d unique results [%s]",
            len(task_ids), len(all_results), len(flat), len(deduped), counts_str,
        )

        ti.xcom_push(key='results', value=deduped)
        return deduped
