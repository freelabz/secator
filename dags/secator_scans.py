"""Airflow DAG entry point for secator scans.

Place this file (or symlink it) in Airflow's ``dags_folder``.
At DAG parse time it discovers all secator scan YAML configs and
generates a DAG for each one.

Generated DAGs will appear in the Airflow UI as:
    secator_scan_domain
    secator_scan_host
    ...
"""

from secator.airflow.dag_factory.scan_dag import generate_all_scan_dags

_dags = generate_all_scan_dags()

# Register in module globals so Airflow's DagBag discovers them
for _dag_id, _dag in _dags.items():
    globals()[_dag_id] = _dag
