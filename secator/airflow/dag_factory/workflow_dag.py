"""Dynamic Airflow DAG generator for secator workflows.

Reads secator YAML workflow configs (e.g., ``url_crawl.yaml``,
``subdomain_recon.yaml``) and generates Airflow DAG objects at parse time.

This replaces ``secator/runners/workflow.py::build_celery_workflow()``.

Mapping from Celery canvas primitives to Airflow constructs:
    - ``chain(a, b, c)``          ->  ``a >> b >> c`` (linear dependency)
    - ``group(a, b, c)``          ->  Tasks inside a ``TaskGroup`` with no
                                      mutual dependency (Airflow auto-parallelises)
    - ``forward_results``         ->  ``SecatorBridgeOperator`` after the group
    - ``mark_runner_started``     ->  ``on_execute_callback``
    - ``mark_runner_completed``   ->  ``on_success_callback``
    - ``if: <condition>``         ->  Condition evaluated inside operator's
                                      ``execute()`` -> ``AirflowSkipException``
    - ``targets_:``               ->  XCom pull + ``extract_targets()`` inside
                                      the operator's ``execute()``

Example generated DAG for ``url_crawl``::

    httpx >> [katana, gospider] >> bridge_crawl >> nuclei
"""

import logging
from datetime import timedelta

from airflow import DAG
from airflow.utils.task_group import TaskGroup

from secator.airflow.operators.secator_task import SecatorTaskOperator
from secator.airflow.operators.secator_bridge import SecatorBridgeOperator
from secator.airflow.callbacks import on_task_success, on_task_failure, on_dag_success
from secator.airflow.config import DEFAULT_TAGS

logger = logging.getLogger(__name__)

DEFAULT_ARGS = {
    'owner': 'secator',
    'depends_on_past': False,
    'retries': 1,
    'retry_delay': timedelta(minutes=1),
    'execution_timeout': timedelta(hours=4),
    'on_success_callback': on_task_success,
    'on_failure_callback': on_task_failure,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_workflow_dag(workflow_name, config, dag_id_prefix='secator_workflow'):
    """Generate an Airflow DAG from a secator workflow config.

    Args:
        workflow_name (str): Workflow name (e.g., 'url_crawl').
        config: TemplateLoader or dict-like config with ``tasks`` key.
        dag_id_prefix (str): Prefix for the DAG id.

    Returns:
        airflow.DAG: The generated DAG.
    """
    dag_id = f'{dag_id_prefix}_{workflow_name}'
    description = ''
    if hasattr(config, 'description'):
        description = config.description or ''
    elif isinstance(config, dict):
        description = config.get('description', '')

    dag = DAG(
        dag_id=dag_id,
        default_args=DEFAULT_ARGS,
        description=description or f'Secator workflow: {workflow_name}',
        schedule=None,  # manual or triggered by scan DAGs
        catchup=False,
        tags=DEFAULT_TAGS + ['workflow', workflow_name],
        params={
            'targets': [],
            'options': {},
            'workspace': 'default',
        },
        render_template_as_native_obj=True,
        on_success_callback=on_dag_success,
    )

    tasks_config = _get_tasks_config(config)
    if not tasks_config:
        logger.warning("Workflow '%s' has no tasks section", workflow_name)
        return dag

    with dag:
        _build_dag_tasks(tasks_config, workflow_name, dag)

    return dag


def build_workflow_task_group(workflow_name, config, dag, group_id=None):
    """Build a TaskGroup containing a workflow's tasks inside an existing DAG.

    Used by scan DAG generator to embed workflows as TaskGroups within a scan DAG.

    Args:
        workflow_name (str): Workflow name.
        config: TemplateLoader or dict-like workflow config.
        dag (airflow.DAG): Parent DAG to attach to.
        group_id (str): TaskGroup id. Defaults to ``wf_{workflow_name}``.

    Returns:
        TaskGroup: The created TaskGroup, or None if empty.
    """
    gid = group_id or f'wf_{_sanitize_id(workflow_name)}'
    tasks_config = _get_tasks_config(config)
    if not tasks_config:
        return None

    with TaskGroup(group_id=gid, dag=dag) as tg:
        _build_dag_tasks(tasks_config, workflow_name, dag)

    return tg


def generate_all_workflow_dags():
    """Auto-generate DAGs for all discovered secator workflow configs.

    Called from the DAGs directory entry point (``dags/secator_workflows.py``).

    Returns:
        dict[str, DAG]: Mapping of dag_id -> DAG.
    """
    from secator.loader import get_configs_by_type

    dags = {}
    for config in get_configs_by_type('workflow'):
        name = config.name if hasattr(config, 'name') else config.get('name', '')
        try:
            dag = build_workflow_dag(name, config)
            dags[dag.dag_id] = dag
        except Exception:
            logger.exception("Failed to generate DAG for workflow '%s'", name)
    return dags


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _get_tasks_config(config):
    """Extract the ``tasks`` section from a config object."""
    if hasattr(config, 'tasks'):
        t = config.tasks
        return t.toDict() if hasattr(t, 'toDict') else dict(t)
    if isinstance(config, dict):
        return config.get('tasks', {})
    return {}


def _sanitize_id(name):
    """Sanitize a string for use as an Airflow task/group id."""
    return name.replace('/', '_').replace('.', '_').replace('-', '_')


def _parse_task_nodes(tasks_config):
    """Parse the ``tasks:`` YAML section into an ordered list of node dicts.

    Each node is either ``{'type': 'task', ...}`` or ``{'type': 'group', ...}``.

    Handles:
        - Regular tasks: sequential execution
        - ``_group/*``: parallel execution (Celery ``group``)
        - ``task_name/alias``: aliased tasks (e.g., ``dnsx/brute``)
    """
    nodes = []
    for key, task_config in tasks_config.items():
        task_config = task_config or {}

        if key.startswith('_group'):
            group_name = key.split('/')[-1] if '/' in key else 'parallel'
            children = []
            for child_key, child_config in task_config.items():
                child_config = child_config or {}
                children.append(_make_task_node(child_key, child_config))
            nodes.append({
                'type': 'group',
                'name': group_name,
                'children': children,
            })
        else:
            nodes.append(_make_task_node(key, task_config))

    return nodes


def _make_task_node(key, config):
    """Build a single task node dict from a YAML key + config."""
    parts = key.split('/')
    task_name = parts[0]
    alias = parts[1] if len(parts) > 1 else None
    return {
        'type': 'task',
        'name': task_name,
        'alias': alias,
        'node_id': key,
        'opts': {k: v for k, v in config.items()
                 if k not in ('if', 'targets_', 'description')},
        'description': config.get('description', ''),
        'condition': config.get('if'),
        'extractors': config.get('targets_', []),
    }


def _build_dag_tasks(tasks_config, workflow_name, dag):
    """Create Airflow operators from parsed task nodes and wire dependencies.

    This is the core wiring logic that mirrors ``Workflow.build_celery_workflow()``.

    Returns:
        BaseOperator | None: The last operator in the chain (for downstream wiring).
    """
    nodes = _parse_task_nodes(tasks_config)
    previous = None
    # Track the last bridge/task that holds accumulated results so that
    # tasks inside groups (which have no direct upstream) can pull from it.
    previous_results_task_id = None

    for node in nodes:
        if node['type'] == 'task':
            current = _create_task_operator(
                node, workflow_name, dag,
                upstream_results_task_id=previous_results_task_id,
            )
            previous_results_task_id = current.task_id
        elif node['type'] == 'group':
            current = _create_group(
                node, workflow_name, dag,
                upstream_results_task_id=previous_results_task_id,
            )
            # The bridge at the end of the group is the new results source
            previous_results_task_id = current.task_id
        else:
            continue

        if current is None:
            continue

        if previous is not None:
            previous >> current

        previous = current

    return previous


def _create_task_operator(node, workflow_name, dag, upstream_results_task_id=None):
    """Create a SecatorTaskOperator from a task node dict.

    Args:
        node (dict): Parsed task node.
        workflow_name (str): Parent workflow name (for context).
        dag (DAG): Parent DAG.
        upstream_results_task_id (str): Task ID of the previous bridge/task
            that holds accumulated results (for tasks inside groups that have
            no direct upstream DAG relatives).

    Returns:
        SecatorTaskOperator
    """
    task_id = _sanitize_id(node['node_id'])
    # Ensure unique task_id within the DAG by prefixing if needed
    existing_ids = {t.task_id for t in dag.tasks}
    if task_id in existing_ids:
        task_id = f"{_sanitize_id(workflow_name)}_{task_id}"

    return SecatorTaskOperator(
        task_id=task_id,
        task_name=node['name'],
        opts=node.get('opts', {}),
        context={
            'node_id': node.get('node_id', task_id),
            'node_name': node['name'],
            'extractors': node.get('extractors', []),
            'condition': node.get('condition'),
            'upstream_results_task_id': upstream_results_task_id,
        },
        skip_if_no_inputs=bool(node.get('extractors')),
        dag=dag,
    )


def _create_group(node, workflow_name, dag, upstream_results_task_id=None):
    """Create a TaskGroup with parallel tasks and a trailing bridge operator.

    Maps to Celery's ``group(...) | forward_results.s()``.

    Args:
        node (dict): Group node with ``children``.
        workflow_name (str): Parent workflow name.
        dag (DAG): Parent DAG.
        upstream_results_task_id (str): Task ID of the previous bridge/task
            that holds accumulated results.

    Returns:
        SecatorBridgeOperator: The bridge operator (acts as group exit point).
    """
    group_name = _sanitize_id(node['name'])
    child_tasks = []

    with TaskGroup(group_id=f"group_{group_name}", dag=dag):
        for child_node in node.get('children', []):
            child_op = _create_task_operator(
                child_node, workflow_name, dag,
                upstream_results_task_id=upstream_results_task_id,
            )
            child_tasks.append(child_op)

        bridge = SecatorBridgeOperator(
            task_id=f"bridge_{group_name}",
            pull_from_task_ids=[t.task_id for t in child_tasks],
            dag=dag,
        )

        for child_op in child_tasks:
            child_op >> bridge

    return bridge
