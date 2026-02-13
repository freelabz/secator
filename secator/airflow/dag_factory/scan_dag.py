"""Dynamic Airflow DAG generator for secator scans.

Reads secator YAML scan configs (e.g., ``domain.yaml``, ``host.yaml``) and
generates Airflow DAG objects.  Each scan chains multiple workflows
sequentially, with results flowing between them via XCom.

This replaces ``secator/runners/scan.py::build_celery_workflow()``.

Architecture decision: workflows are embedded as **TaskGroups** within the scan
DAG rather than using ``TriggerDagRunOperator``.  This keeps all result data
(XCom) within a single DAG run, avoiding the complexity of cross-DAG data
passing.

Example generated DAG for the ``domain`` scan::

    [wf_domain_recon] >> [wf_subdomain_recon] >> [wf_host_recon] >> [wf_url_crawl]
        (TaskGroup)          (TaskGroup)            (TaskGroup)        (TaskGroup)

Each TaskGroup internally contains the workflow's task chain/groups, with a
bridge operator at the end to aggregate results for the next workflow.
"""

import logging
from airflow import DAG
from airflow.utils.task_group import TaskGroup

from secator.airflow.operators.secator_bridge import SecatorBridgeOperator
from secator.airflow.callbacks import on_dag_success
from secator.airflow.dag_factory.workflow_dag import (
    DEFAULT_ARGS,
    _build_dag_tasks,
    _get_tasks_config,
    _sanitize_id,
)
from secator.airflow.config import DEFAULT_TAGS

logger = logging.getLogger(__name__)


def build_scan_dag(scan_name, config, dag_id_prefix='secator_scan'):
    """Generate an Airflow DAG from a secator scan config.

    A scan chains multiple workflows sequentially.  Each workflow becomes a
    TaskGroup within this DAG, and results flow between workflows via
    ``SecatorBridgeOperator`` nodes.

    Args:
        scan_name (str): Scan name (e.g., 'domain', 'host').
        config: TemplateLoader or dict-like config with ``workflows`` key.
        dag_id_prefix (str): Prefix for the DAG id.

    Returns:
        airflow.DAG: The generated DAG.
    """
    dag_id = f'{dag_id_prefix}_{scan_name}'
    description = ''
    if hasattr(config, 'description'):
        description = config.description or ''
    elif isinstance(config, dict):
        description = config.get('description', '')

    dag = DAG(
        dag_id=dag_id,
        default_args=DEFAULT_ARGS,
        description=description or f'Secator scan: {scan_name}',
        schedule=None,
        catchup=False,
        tags=DEFAULT_TAGS + ['scan', scan_name],
        params={
            'targets': [],
            'options': {},
            'workspace': 'default',
        },
        render_template_as_native_obj=True,
        on_success_callback=on_dag_success,
    )

    workflows_config = _get_workflows_config(config)
    if not workflows_config:
        logger.warning("Scan '%s' has no workflows section", scan_name)
        return dag

    with dag:
        previous_bridge = None

        for wf_name, wf_opts in workflows_config.items():
            wf_opts = wf_opts or {}

            # Load the workflow config
            wf_config = _load_workflow_config(wf_name)
            if wf_config is None:
                logger.error("Workflow '%s' not found, skipping in scan '%s'", wf_name, scan_name)
                continue

            tasks_config = _get_tasks_config(wf_config)
            if not tasks_config:
                continue

            # Inject scan-level extractors into the workflow's first task context
            scan_extractors = wf_opts.get('targets_', [])
            scan_condition = wf_opts.get('if')
            if scan_extractors or scan_condition:
                first_key = next(iter(tasks_config))
                first_cfg = tasks_config[first_key] or {}

                # If the first entry is a group, inject into each child task
                if first_key.startswith('_group') and isinstance(first_cfg, dict):
                    for child_key, child_cfg in first_cfg.items():
                        child_cfg = child_cfg or {}
                        if not isinstance(child_cfg, dict):
                            continue
                        if scan_extractors:
                            existing = child_cfg.get('targets_', [])
                            child_cfg['targets_'] = existing + scan_extractors
                        if scan_condition and not child_cfg.get('if'):
                            child_cfg['if'] = scan_condition
                        first_cfg[child_key] = child_cfg
                else:
                    if scan_extractors:
                        existing = first_cfg.get('targets_', [])
                        first_cfg['targets_'] = existing + scan_extractors
                    if scan_condition and not first_cfg.get('if'):
                        first_cfg['if'] = scan_condition

                tasks_config[first_key] = first_cfg

            # Create TaskGroup for this workflow
            sanitized_wf_name = _sanitize_id(wf_name.split('/')[0])
            with TaskGroup(group_id=f"wf_{sanitized_wf_name}", dag=dag) as wf_group:
                last_op = _build_dag_tasks(tasks_config, wf_name, dag)

                # Bridge at the end of each workflow to aggregate for the next
                wf_bridge = SecatorBridgeOperator(
                    task_id=f"bridge_wf_{sanitized_wf_name}",
                    dag=dag,
                )

                # Wire last task/group in workflow -> bridge
                if last_op is not None:
                    last_op >> wf_bridge

            # Wire sequential workflow groups
            if previous_bridge is not None:
                previous_bridge >> wf_group

            previous_bridge = wf_bridge

    return dag


def generate_all_scan_dags():
    """Auto-generate DAGs for all discovered secator scan configs.

    Called from the DAGs directory entry point (``dags/secator_scans.py``).

    Returns:
        dict[str, DAG]: Mapping of dag_id -> DAG.
    """
    from secator.loader import get_configs_by_type

    dags = {}
    for config in get_configs_by_type('scan'):
        name = config.name if hasattr(config, 'name') else config.get('name', '')
        try:
            dag = build_scan_dag(name, config)
            dags[dag.dag_id] = dag
        except Exception:
            logger.exception("Failed to generate DAG for scan '%s'", name)
    return dags


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _get_workflows_config(config):
    """Extract the ``workflows`` section from a scan config."""
    if hasattr(config, 'workflows'):
        w = config.workflows
        return w.toDict() if hasattr(w, 'toDict') else dict(w)
    if isinstance(config, dict):
        return config.get('workflows', {})
    return {}


def _load_workflow_config(wf_name):
    """Load a workflow TemplateLoader config by name.

    Args:
        wf_name (str): Workflow name (may contain ``/alias``).

    Returns:
        TemplateLoader or None
    """
    from secator.template import TemplateLoader

    base_name = wf_name.split('/')[0]
    try:
        config = TemplateLoader(name=f'workflow/{base_name}')
        if not config or not config.get('name'):
            return None
        return config
    except Exception:
        logger.exception("Failed to load workflow config: %s", base_name)
        return None
