"""Airflow DAG entry point for secator workflows.

Place this file (or symlink it) in Airflow's ``dags_folder``.
At DAG parse time it discovers all secator workflow YAML configs and
generates a DAG for each one.

Generated DAGs will appear in the Airflow UI as:
    secator_workflow_url_crawl
    secator_workflow_subdomain_recon
    secator_workflow_domain_recon
    ...
"""

from secator.airflow.dag_factory.workflow_dag import generate_all_workflow_dags

_dags = generate_all_workflow_dags()

# Register in module globals so Airflow's DagBag discovers them
for _dag_id, _dag in _dags.items():
    globals()[_dag_id] = _dag
