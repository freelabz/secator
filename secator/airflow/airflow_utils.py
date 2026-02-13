"""Utility for real-time result streaming from Airflow DAG runs.

Mirrors ``secator/celery_utils.py::CeleryData`` — polls Airflow task instances,
yields results as each task completes, and drives the Rich progress panel.
"""

import gc
import logging

from contextlib import nullcontext
from time import sleep

from rich.padding import Padding
from rich.panel import Panel
from rich.progress import Progress as RichProgress, SpinnerColumn, TextColumn, TimeElapsedColumn

from secator.airflow.api_client import AirflowAPIClient
from secator.airflow.config import get_poll_frequency
from secator.airflow.utils import deserialize_results, deduplicate_results
from secator.definitions import STATE_COLORS
from secator.output_types import Progress
from secator.rich import console

logger = logging.getLogger(__name__)

# Map Airflow task states to secator state names
AIRFLOW_STATE_MAP = {
    None: 'PENDING',
    'queued': 'PENDING',
    'scheduled': 'PENDING',
    'up_for_retry': 'PENDING',
    'up_for_reschedule': 'PENDING',
    'running': 'RUNNING',
    'restarting': 'RUNNING',
    'deferred': 'RUNNING',
    'success': 'SUCCESS',
    'failed': 'FAILURE',
    'skipped': 'SKIPPED',
    'removed': 'SKIPPED',
    'upstream_failed': 'FAILURE',
}


class AirflowData:
    """Utility to poll an Airflow DAG run and stream results in real-time."""

    @staticmethod
    def iter_results(
        dag_id,
        run_id,
        ids_map=None,
        description=True,
        print_remote_info=True,
        print_remote_title='Results',
    ):
        """Poll an Airflow DAG run and yield results as tasks complete.

        Mirrors ``CeleryData.iter_results()``.  On each poll cycle the method
        checks which tasks have finished since the last cycle, pulls their
        results from XCom, and yields them immediately so the caller sees
        real-time output.

        Args:
            dag_id (str): Airflow DAG id.
            run_id (str): Airflow DAG run id.
            ids_map (dict): Task display metadata keyed by short task id.
                Each value is a dict with ``name``, ``descr``, etc.
            description (bool): Show task descriptions in progress panel.
            print_remote_info (bool): Display live Rich progress panel.
            print_remote_title (str): Title for the progress panel.

        Yields:
            secator.output_types.OutputType: Deserialized result items.
        """
        client = AirflowAPIClient()
        poll_interval = get_poll_frequency()
        ids_map = ids_map or {}

        # Build Rich progress panel (same style as CeleryData)
        if print_remote_info:
            class PanelProgress(RichProgress):
                def get_renderables(self):
                    yield Padding(Panel(
                        self.make_tasks_table(self.tasks),
                        title=print_remote_title,
                        border_style='bold gold3',
                        expand=False,
                        highlight=True), pad=(2, 0, 0, 0))
            progress = PanelProgress(
                SpinnerColumn('dots'),
                TextColumn('{task.fields[descr]}  ') if description else '',
                TextColumn('[bold cyan]{task.fields[name]}[/]'),
                TextColumn('{task.fields[state]:<20}'),
                TimeElapsedColumn(),
                TextColumn('{task.fields[count]}'),
                TextColumn('{task.fields[progress]}%'),
                auto_refresh=False,
                transient=False,
                console=console,
            )
        else:
            progress = nullcontext()

        # Track which tasks we already yielded results for
        yielded_tasks = set()
        progress_cache = {}  # airflow task_id -> rich progress task id

        with progress:
            # Init progress rows for known tasks
            if print_remote_info and ids_map:
                for tid, meta in ids_map.items():
                    state = meta.get('state', 'PENDING')
                    state_str = f'[{STATE_COLORS.get(state, "dim")}]{state}[/]'
                    progress_cache[tid] = progress.add_task(
                        '', advance=0,
                        name=meta.get('name', tid),
                        descr=meta.get('descr', ''),
                        state=state_str,
                        count='',
                        progress=0,
                    )

            for status in client.poll_dag_run(dag_id, run_id, interval=poll_interval):
                dag_state = status.get('state', 'unknown')
                task_instances = status.get('task_instances', [])

                for ti in task_instances:
                    tid = ti['task_id']

                    # Skip bridge tasks in display
                    if 'bridge' in tid:
                        continue

                    airflow_state = ti.get('state')
                    sec_state = AIRFLOW_STATE_MAP.get(airflow_state, 'PENDING')

                    # Yield results from newly completed tasks
                    is_done = sec_state in ('SUCCESS', 'FAILURE', 'SKIPPED')
                    if is_done and tid not in yielded_tasks:
                        yielded_tasks.add(tid)
                        if sec_state == 'SUCCESS':
                            try:
                                raw = client.get_xcom(dag_id, run_id, tid, key='results')
                                if isinstance(raw, list) and raw:
                                    results = deserialize_results(deduplicate_results(raw))
                                    yield from results
                            except Exception:
                                pass

                    # Compute display values
                    count = ''
                    if sec_state == 'SUCCESS' and tid in yielded_tasks:
                        try:
                            raw = client.get_xcom(dag_id, run_id, tid, key='results')
                            if isinstance(raw, list):
                                count = f'{len(raw)} results'
                        except Exception:
                            pass

                    task_progress = 0
                    if sec_state in ('SUCCESS', 'SKIPPED'):
                        task_progress = 100
                    elif sec_state == 'RUNNING':
                        task_progress = 50

                    # Resolve display name from ids_map
                    short_id = tid.rsplit('.', 1)[-1] if '.' in tid else tid
                    meta = ids_map.get(short_id, {})
                    display_name = meta.get('name', short_id)
                    descr = meta.get('descr', '')
                    state_str = f'[{STATE_COLORS.get(sec_state, "dim")}]{sec_state}[/]'

                    # Update progress panel
                    if print_remote_info:
                        if tid not in progress_cache:
                            progress_cache[tid] = progress.add_task(
                                '', advance=0, name=display_name, descr=descr,
                                state=state_str, count=count, progress=task_progress)
                        else:
                            progress.update(
                                progress_cache[tid], name=display_name, descr=descr,
                                state=state_str, count=count, progress=task_progress)

                # Yield overall progress
                if task_instances:
                    visible = [t for t in task_instances if 'bridge' not in t['task_id']]
                    total = len(visible)
                    done = sum(
                        1 for t in visible
                        if t['state'] in ('success', 'failed', 'skipped')
                    )
                    percent = int(done * 100 / total) if total > 0 else 0
                    yield Progress(percent=percent)

                if print_remote_info:
                    progress.refresh()

                gc.collect()

            # Mark all progress tasks as complete
            if print_remote_info:
                for pid in progress_cache.values():
                    progress.update(pid, advance=100)
                progress.refresh()

    @staticmethod
    def build_ids_map(config, runner_type):
        """Build a task display metadata map from workflow/scan config.

        Resolves task node_ids to display names and descriptions, mirroring
        the ``ids_map`` that ``CeleryData`` builds from Celery subtask metadata.

        Args:
            config: TemplateLoader config for the runner.
            runner_type (str): Runner type ('task', 'workflow', 'scan').

        Returns:
            dict: Mapping of sanitized task id -> {name, descr, state, ...}.
        """
        ids_map = {}
        try:
            from secator.loader import get_configs_by_type
            configs = get_configs_by_type(runner_type)
            for cfg in configs:
                if cfg.name != config.name:
                    continue
                tasks = cfg.tasks or {}
                if hasattr(tasks, 'toDict'):
                    tasks = tasks.toDict()
                for key, val in tasks.items():
                    val = val or {}
                    if key.startswith('_group'):
                        if isinstance(val, dict):
                            for child_key, child_val in val.items():
                                child_val = child_val or {}
                                if not isinstance(child_val, dict):
                                    continue
                                sanitized = child_key.replace('/', '_').replace('.', '_').replace('-', '_')
                                ids_map[sanitized] = {
                                    'name': child_key,
                                    'descr': child_val.get('description', ''),
                                    'state': 'PENDING',
                                    'count': 0,
                                    'progress': 0,
                                }
                    else:
                        sanitized = key.replace('/', '_').replace('.', '_').replace('-', '_')
                        ids_map[sanitized] = {
                            'name': key,
                            'descr': val.get('description', '') if isinstance(val, dict) else '',
                            'state': 'PENDING',
                            'count': 0,
                            'progress': 0,
                        }
                break
        except Exception:
            logger.debug("Failed to build ids_map for %s/%s", runner_type, config.name, exc_info=True)
        return ids_map
