"""Secator Airflow integration.

Provides Apache Airflow operators, DAG generators, and utilities to migrate
secator's orchestration layer from Celery to Airflow.

Modules:
    operators   - Custom Airflow operators for secator task execution
    dag_factory - Dynamic DAG generation from secator YAML configs
    callbacks   - Airflow callbacks for MongoDB persistence and hooks
    xcom        - Custom XCom backend for large result sets
    config      - Airflow-specific configuration bridge
    utils       - Serialization, extraction, and shared utilities
    api_client  - Airflow REST API client for CLI integration
"""
