"""Dynamic Airflow DAG generator for individual secator tasks.

Generates one DAG per discovered secator task class (e.g., ``httpx``, ``nmap``,
``nuclei``).  Each DAG contains a single ``SecatorTaskOperator`` that runs the
tool with targets and options passed via DAG ``params``.

Generated DAGs appear in the Airflow UI as:
    secator_task_httpx
    secator_task_nmap
    secator_task_nuclei
    ...
"""

import logging
from datetime import timedelta

from airflow import DAG

from secator.airflow.operators.secator_task import SecatorTaskOperator
from secator.airflow.callbacks import on_task_success, on_task_failure
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


def build_task_dag(task_name, dag_id_prefix='secator_task'):
    """Generate an Airflow DAG for a single secator task.

    Args:
        task_name (str): Task class name (e.g., 'httpx', 'nmap').
        dag_id_prefix (str): Prefix for the DAG id.

    Returns:
        airflow.DAG: The generated DAG.
    """
    dag_id = f'{dag_id_prefix}_{task_name}'

    dag = DAG(
        dag_id=dag_id,
        default_args=DEFAULT_ARGS,
        description=f'Secator task: {task_name}',
        schedule=None,
        catchup=False,
        tags=DEFAULT_TAGS + ['task', task_name],
        params={
            'targets': [],
            'options': {},
            'workspace': 'default',
        },
        render_template_as_native_obj=True,
    )

    with dag:
        SecatorTaskOperator(
            task_id=task_name,
            task_name=task_name,
            dag=dag,
        )

    return dag


def generate_all_task_dags():
    """Auto-generate DAGs for all discovered secator task classes.

    Called from the DAGs directory entry point (``dags/secator_tasks.py``).

    Returns:
        dict[str, DAG]: Mapping of dag_id -> DAG.
    """
    from secator.loader import discover_tasks

    dags = {}
    for task_cls in discover_tasks():
        name = task_cls.__name__
        try:
            dag = build_task_dag(name)
            dags[dag.dag_id] = dag
        except Exception:
            logger.exception("Failed to generate DAG for task '%s'", name)
    return dags
