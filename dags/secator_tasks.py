"""Airflow DAG entry point for individual secator tasks.

Place this file (or symlink it) in Airflow's ``dags_folder``.
At DAG parse time it discovers all secator task classes and
generates a DAG for each one.

Generated DAGs will appear in the Airflow UI as:
    secator_task_httpx
    secator_task_nmap
    secator_task_nuclei
    ...
"""

from secator.airflow.dag_factory.task_dag import generate_all_task_dags

_dags = generate_all_task_dags()

# Register in module globals so Airflow's DagBag discovers them
for _dag_id, _dag in _dags.items():
    globals()[_dag_id] = _dag
