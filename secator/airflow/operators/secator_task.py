"""SecatorTaskOperator - executes a single secator task (security tool) in Airflow.

This operator replaces `secator/celery.py::run_command()`. It wraps secator's
Command/Task runner to execute an external CLI tool (nmap, httpx, nuclei, etc.)
and pushes structured results to XCom for downstream consumption.

Usage in a DAG::

    scan_nmap = SecatorTaskOperator(
        task_id='nmap',
        task_name='nmap',
        targets=['192.168.1.0/24'],
        opts={'ports': '1-1000', 'rate_limit': 1000},
    )
"""

import logging
import uuid

from airflow.exceptions import AirflowSkipException
from airflow.models import BaseOperator

from secator.airflow.utils import (
    deduplicate_results,
    extract_targets,
    flatten_results,
)

logger = logging.getLogger(__name__)


class SecatorTaskOperator(BaseOperator):
    """Execute a secator task (single security tool wrapper).

    This operator:
    1. Resolves the secator task class by name
    2. Pulls upstream results from XCom and applies target extractors
    3. Evaluates conditional execution (``if:`` from YAML)
    4. Runs the tool via secator's subprocess Command runner
    5. Pushes serialized results to XCom

    Args:
        task_name: Name of the secator task class (e.g., 'nmap', 'httpx', 'nuclei').
        targets: Explicit list of targets. If empty, extracted from upstream results.
        opts: Task-specific options dict passed to the tool wrapper.
        context: Run context dict (workspace_name, node_id, extractors, condition, etc.).
        upstream_results_key: XCom key to pull upstream results from.
        skip_if_no_inputs: Skip execution (AirflowSkipException) if no targets resolved.
    """

    template_fields = ('targets', 'opts', 'context')
    ui_color = '#f0c040'
    ui_fgcolor = '#000000'

    def __init__(
        self,
        task_name,
        targets=None,
        opts=None,
        context=None,
        upstream_results_key='results',
        skip_if_no_inputs=False,
        **kwargs,
    ):
        # Run even if some upstream tasks were skipped
        kwargs.setdefault('trigger_rule', 'none_failed_min_one_success')
        super().__init__(**kwargs)
        self.task_name = task_name
        self.targets = targets or []
        self.opts = opts or {}
        self.context = context or {}
        self.upstream_results_key = upstream_results_key
        self.skip_if_no_inputs = skip_if_no_inputs

    def execute(self, context):
        from secator.runners.task import Task
        from secator.output_types import Error, Progress

        ti = context['ti']

        # 1. Resolve task class
        task_cls = Task.get_task_class(self.task_name)

        # 2. Gather upstream results from XCom
        upstream_results = self._pull_upstream_results(ti)

        # 3. Resolve targets: explicit targets or extracted from upstream
        targets = list(self.targets) if self.targets else []
        extractors = self.context.get('extractors', [])
        if extractors and upstream_results:
            extracted = extract_targets(upstream_results, extractors)
            if extracted:
                targets = extracted
                self.log.info("Extracted %d targets from upstream results", len(targets))

        # If no explicit targets and no extractors produced any, use dag_run.conf
        if not targets:
            dag_conf = context.get('dag_run').conf or {}
            dag_targets = dag_conf.get('targets', [])
            if dag_targets:
                targets = list(dag_targets)

        # 4. Evaluate conditional execution
        condition = self.context.get('condition')
        if condition:
            self._evaluate_condition(condition, targets, context)

        # 5. Skip if no inputs
        if not targets and self.skip_if_no_inputs:
            self.log.info("Skipping %s: no targets", self.task_name)
            ti.xcom_push(key='results', value=[])
            raise AirflowSkipException(f"No targets for {self.task_name}")

        # 6. Build task options
        run_opts = self._build_run_opts(context)

        # 7. Check if chunking is needed
        chunk_size = getattr(task_cls, 'input_chunk_size', 0)
        needs_chunk = (
            len(targets) > 1
            and chunk_size
            and chunk_size != -1
            and getattr(task_cls, 'file_flag', None) is None
        )

        if needs_chunk:
            chunks = [targets[i:i + chunk_size] for i in range(0, len(targets), chunk_size)]
            self.log.info(
                "Chunking %s: %d targets into %d chunks (size=%d)",
                self.task_name, len(targets), len(chunks), chunk_size,
            )
        else:
            chunks = [targets]

        # 8. Execute task (once per chunk)
        results = []
        errors = []
        for ix, chunk in enumerate(chunks):
            if needs_chunk:
                self.log.info("Running %s chunk %d/%d on %d target(s)", self.task_name, ix + 1, len(chunks), len(chunk))
                chunk_opts = run_opts.copy()
                chunk_opts['chunk'] = ix + 1
                chunk_opts['chunk_count'] = len(chunks)
            else:
                self.log.info("Running %s on %d target(s)", self.task_name, len(chunk))
                chunk_opts = run_opts

            task_instance = task_cls(inputs=chunk, **chunk_opts)
            for item in task_instance:
                if isinstance(item, Error):
                    errors.append(item.toDict())
                    self.log.error("Task error: %s", item.message)
                elif isinstance(item, Progress):
                    pass
                elif hasattr(item, 'toDict'):
                    results.append(item.toDict())
                elif isinstance(item, str):
                    self.log.info(item)

        # 9. Push results
        self.log.info(
            "%s completed: %d results, %d errors, return_code=%s",
            self.task_name, len(results), len(errors),
            getattr(task_instance, 'return_code', 'N/A'),
        )
        ti.xcom_push(key='results', value=results)
        ti.xcom_push(key='errors', value=errors)
        ti.xcom_push(key='task_name', value=self.task_name)

        return results

    def _pull_upstream_results(self, ti):
        """Pull and flatten results from all upstream tasks via XCom.

        When a task is inside a TaskGroup (parallel group), it has no direct
        upstream DAG relatives.  In that case, fall back to the
        ``upstream_results_task_id`` stored in context by the DAG builder —
        this points to the previous bridge or standalone task that holds the
        accumulated results from all prior workflow steps.

        Args:
            ti: Airflow TaskInstance.

        Returns:
            list[dict]: Flat, deduplicated list of upstream results.
        """
        all_results = []
        upstream_ops = self.get_direct_relatives(upstream=True)
        for op in upstream_ops:
            pulled = ti.xcom_pull(task_ids=op.task_id, key=self.upstream_results_key)
            if pulled:
                all_results.extend(pulled if isinstance(pulled, list) else [pulled])

        # If no direct upstream (task is inside a parallel group), pull from
        # the previous bridge/task identified at DAG build time.
        if not all_results:
            fallback_id = self.context.get('upstream_results_task_id')
            if fallback_id:
                pulled = ti.xcom_pull(task_ids=fallback_id, key=self.upstream_results_key)
                if pulled:
                    self.log.info("Pulled %d results from upstream %s", len(pulled), fallback_id)
                    all_results.extend(pulled if isinstance(pulled, list) else [pulled])

        return deduplicate_results(flatten_results(all_results))

    def _evaluate_condition(self, condition, targets, context):
        """Evaluate a conditional expression from YAML ``if:`` clause.

        Raises AirflowSkipException if the condition is not met.

        Args:
            condition (str): Python expression string.
            targets (list): Current target list.
            context: Airflow context dict.
        """
        from dotmap import DotMap
        dag_conf = (context.get('dag_run').conf or {}) if context.get('dag_run') else {}
        dag_opts = dag_conf.get('options', {})
        eval_ctx = {
            'opts': DotMap(dag_opts),
            'targets': targets,
        }
        safe_globals = {'__builtins__': {'len': len}}
        try:
            result = eval(condition, safe_globals, eval_ctx)
            if not result:
                self.log.info("Condition not met, skipping: %s", condition)
                raise AirflowSkipException(f"Condition not met: {condition}")
        except AirflowSkipException:
            raise
        except Exception as e:
            self.log.warning("Condition eval error for '%s': %s", condition, e)

    def _build_run_opts(self, context):
        """Build the run_opts dict for the secator task.

        Args:
            context: Airflow context dict.

        Returns:
            dict: Options for task instantiation.
        """
        dag_conf = (context.get('dag_run').conf or {}) if context.get('dag_run') else {}
        dag_opts = dag_conf.get('options', {})
        workspace = dag_conf.get('workspace', 'default')

        run_opts = {**dag_opts, **self.opts}
        run_opts.pop('backend', None)  # force local execution inside worker
        run_opts.update({
            'sync': True,
            'print_cmd': True,
            'print_item': True,
            'print_line': True,
            'enable_hooks': True,
            'enable_reports': False,
            'enable_duplicate_check': False,
            'has_parent': True,
            'skip_if_no_inputs': self.skip_if_no_inputs,
        })

        # Merge context
        task_context = self.context.copy()
        task_context['workspace_name'] = workspace
        task_context.setdefault('celery_id', str(uuid.uuid4()))
        run_opts['context'] = task_context

        return run_opts
