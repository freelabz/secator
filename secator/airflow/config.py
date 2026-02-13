"""Airflow-specific configuration bridge.

Maps secator's existing configuration system to Airflow concepts like
worker queues, pools, timeouts, and connections.
"""

import os

from secator.config import CONFIG


# Airflow connection / API settings (overridable via environment)
AIRFLOW_API_URL = os.environ.get('SECATOR_AIRFLOW_API_URL', 'http://localhost:8080/api/v2')
AIRFLOW_USERNAME = os.environ.get('SECATOR_AIRFLOW_USERNAME', 'admin')


def _read_standalone_password():
    """Read the auto-generated password from Airflow standalone mode."""
    path = os.path.expanduser('~/airflow/simple_auth_manager_passwords.json.generated')
    try:
        import json
        with open(path) as f:
            data = json.load(f)
        return data.get('admin', 'admin')
    except Exception:
        return 'admin'


AIRFLOW_PASSWORD = os.environ.get('SECATOR_AIRFLOW_PASSWORD') or _read_standalone_password()
AIRFLOW_DAGS_FOLDER = os.environ.get('SECATOR_AIRFLOW_DAGS_FOLDER', '/opt/airflow/dags')

# Pool name mapping from secator task profiles
POOL_MAP = {
    'small': 'secator_small',
    'medium': 'secator_medium',
    'large': 'secator_large',
    'io': 'secator_io',
}

# Default DAG tags
DEFAULT_TAGS = ['secator']


def get_worker_queue(task_cls):
    """Map a secator task class profile to an Airflow queue name.

    Args:
        task_cls: Secator task class (e.g., nmap, httpx).

    Returns:
        str: Airflow queue name.
    """
    profile = task_cls.profile
    if callable(profile):
        return 'default'
    return profile or 'default'


def get_task_pool(task_cls):
    """Map a secator task class to an Airflow pool for concurrency control.

    Args:
        task_cls: Secator task class.

    Returns:
        str: Airflow pool name.
    """
    profile = task_cls.profile if not callable(task_cls.profile) else 'small'
    return POOL_MAP.get(profile, 'secator_default')


def get_task_timeout():
    """Get the maximum execution timeout for tasks (seconds).

    Returns:
        int: Timeout in seconds, or -1 for unlimited.
    """
    return CONFIG.celery.task_max_timeout


def get_memory_limit():
    """Get the memory limit for task processes (MB).

    Returns:
        int: Memory limit in MB, or -1 for unlimited.
    """
    return CONFIG.celery.task_memory_limit_mb


def get_poll_frequency():
    """Get the result polling frequency (seconds).

    Returns:
        int: Poll interval in seconds.
    """
    return CONFIG.runners.poll_frequency


def get_input_chunk_size():
    """Get the default input chunk size for task splitting.

    Returns:
        int: Chunk size.
    """
    return CONFIG.runners.input_chunk_size
