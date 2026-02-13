"""Airflow REST API client for secator CLI integration.

Replaces ``secator/celery_utils.py::CeleryData`` for remote execution.
Provides methods to trigger DAG runs, poll for status, and retrieve results
from a running Airflow cluster.

Targets Airflow 3.x (``/api/v2``, JWT authentication).

Usage::

    from secator.airflow.api_client import AirflowAPIClient

    client = AirflowAPIClient()
    run = client.trigger_dag('secator_workflow_url_crawl', conf={
        'targets': ['https://example.com'],
        'options': {'rate_limit': 100},
    })
    for status in client.poll_dag_run(run['dag_id'], run['dag_run_id']):
        print(status['state'])
    results = client.collect_results(run['dag_id'], run['dag_run_id'])
"""

import logging
from time import sleep

import requests

from secator.airflow.config import (
    AIRFLOW_API_URL,
    AIRFLOW_PASSWORD,
    AIRFLOW_USERNAME,
    get_poll_frequency,
)

logger = logging.getLogger(__name__)


class AirflowAPIClient:
    """Client for the Airflow REST API (``/api/v2``, Airflow 3.x)."""

    def __init__(self, base_url=None, username=None, password=None):
        self.base_url = (base_url or AIRFLOW_API_URL).rstrip('/')
        self.username = username or AIRFLOW_USERNAME
        self.password = password or AIRFLOW_PASSWORD
        self.session = requests.Session()
        self.session.headers['Content-Type'] = 'application/json'
        self._token = None

    def _get_auth_base_url(self):
        """Get the base URL for auth endpoints (strip /api/v2)."""
        url = self.base_url
        for suffix in ('/api/v2', '/api/v1'):
            if url.endswith(suffix):
                return url[:-len(suffix)]
        return url

    def _authenticate(self):
        """Obtain a JWT token from the Airflow auth endpoint."""
        auth_url = f'{self._get_auth_base_url()}/auth/token'
        resp = requests.post(
            auth_url,
            json={'username': self.username, 'password': self.password},
        )
        resp.raise_for_status()
        self._token = resp.json().get('access_token')
        self.session.headers['Authorization'] = f'Bearer {self._token}'
        logger.debug("Authenticated with Airflow at %s", auth_url)

    def _ensure_auth(self):
        """Ensure we have a valid JWT token."""
        if self._token is None:
            self._authenticate()

    def _request(self, method, path, **kwargs):
        """Make an authenticated request, re-authenticating on 401/403."""
        self._ensure_auth()
        url = f'{self.base_url}{path}'
        resp = getattr(self.session, method)(url, **kwargs)
        if resp.status_code in (401, 403):
            self._authenticate()
            resp = getattr(self.session, method)(url, **kwargs)
        return resp

    # ------------------------------------------------------------------
    # DAG runs
    # ------------------------------------------------------------------

    def trigger_dag(self, dag_id, conf=None):
        """Trigger a DAG run.

        Args:
            dag_id (str): The DAG to trigger.
            conf (dict): Configuration passed to the DAG (``params``).

        Returns:
            dict: Airflow DAG run response (contains ``dag_run_id``).

        Raises:
            requests.HTTPError: On non-2xx responses.
        """
        # Ensure DAG is unpaused before triggering
        try:
            self._request('patch', f'/dags/{dag_id}', json={'is_paused': False})
        except Exception:
            pass

        resp = self._request(
            'post',
            f'/dags/{dag_id}/dagRuns',
            json={'conf': conf or {}, 'logical_date': None},
        )
        resp.raise_for_status()
        data = resp.json()
        return data

    def get_dag_run(self, dag_id, run_id):
        """Get the status of a DAG run.

        Args:
            dag_id (str): DAG id.
            run_id (str): DAG run id.

        Returns:
            dict: DAG run state info.
        """
        resp = self._request(
            'get',
            f'/dags/{dag_id}/dagRuns/{run_id}',
        )
        resp.raise_for_status()
        return resp.json()

    def get_task_instances(self, dag_id, run_id):
        """Get all task instances for a DAG run.

        Args:
            dag_id (str): DAG id.
            run_id (str): DAG run id.

        Returns:
            list[dict]: Task instance info dicts.
        """
        resp = self._request(
            'get',
            f'/dags/{dag_id}/dagRuns/{run_id}/taskInstances',
        )
        resp.raise_for_status()
        return resp.json().get('task_instances', [])

    # ------------------------------------------------------------------
    # XCom
    # ------------------------------------------------------------------

    def get_xcom(self, dag_id, run_id, task_id, key='return_value'):
        """Get an XCom value for a specific task instance.

        Args:
            dag_id (str): DAG id.
            run_id (str): DAG run id.
            task_id (str): Task id.
            key (str): XCom key (default: ``return_value``).

        Returns:
            any: Deserialized XCom value, or None.
        """
        try:
            resp = self._request(
                'get',
                f'/dags/{dag_id}/dagRuns/{run_id}'
                f'/taskInstances/{task_id}/xcomEntries/{key}',
            )
            resp.raise_for_status()
            return resp.json().get('value')
        except requests.HTTPError:
            return None

    # ------------------------------------------------------------------
    # Task logs
    # ------------------------------------------------------------------

    def get_task_log(self, dag_id, run_id, task_id, try_number=1):
        """Get logs for a task instance.

        Args:
            dag_id (str): DAG id.
            run_id (str): DAG run id.
            task_id (str): Task id.
            try_number (int): Attempt number.

        Returns:
            str: Log content.
        """
        try:
            resp = self._request(
                'get',
                f'/dags/{dag_id}/dagRuns/{run_id}'
                f'/taskInstances/{task_id}/logs/{try_number}',
            )
            resp.raise_for_status()
            return resp.text
        except requests.HTTPError:
            return ''

    # ------------------------------------------------------------------
    # Polling
    # ------------------------------------------------------------------

    def poll_dag_run(self, dag_id, run_id, interval=None):
        """Poll a DAG run until completion, yielding status updates.

        Replaces ``secator/celery_utils.py::CeleryData.iter_results()``.

        Args:
            dag_id (str): DAG id.
            run_id (str): DAG run id.
            interval (float): Seconds between polls. Defaults to config value.

        Yields:
            dict: Status dict with ``state``, ``dag_id``, ``run_id``, and
                ``task_instances`` (list of task states).
        """
        if interval is None:
            interval = get_poll_frequency()

        terminal_states = {'success', 'failed'}

        while True:
            run = self.get_dag_run(dag_id, run_id)
            state = run.get('state', 'unknown')

            # Get task instance states for progress display
            task_instances = []
            try:
                tis = self.get_task_instances(dag_id, run_id)
                task_instances = [
                    {
                        'task_id': ti['task_id'],
                        'state': ti.get('state', 'unknown'),
                        'duration': ti.get('duration'),
                        'try_number': ti.get('try_number'),
                    }
                    for ti in tis
                ]
            except Exception:
                pass

            yield {
                'state': state,
                'dag_id': dag_id,
                'run_id': run_id,
                'logical_date': run.get('logical_date'),
                'task_instances': task_instances,
            }

            if state in terminal_states:
                break

            sleep(interval)

    # ------------------------------------------------------------------
    # Result collection
    # ------------------------------------------------------------------

    def collect_results(self, dag_id, run_id):
        """Collect all ``results`` XCom values from a completed DAG run.

        Iterates through all task instances that have a ``results`` XCom key
        and returns the merged, deduplicated result set.

        Args:
            dag_id (str): DAG id.
            run_id (str): DAG run id.

        Returns:
            list[dict]: Merged results from all tasks.
        """
        from secator.airflow.utils import deduplicate_results, flatten_results

        all_results = []
        task_instances = self.get_task_instances(dag_id, run_id)

        for ti in task_instances:
            task_id = ti['task_id']
            results = self.get_xcom(dag_id, run_id, task_id, key='results')
            if results and isinstance(results, list):
                all_results.extend(results)

        flat = flatten_results(all_results)
        return deduplicate_results(flat)

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    def is_healthy(self):
        """Check if the Airflow API is reachable and healthy.

        Returns:
            bool: True if the scheduler is healthy.
        """
        try:
            resp = self._request('get', '/monitor/health')
            resp.raise_for_status()
            data = resp.json()
            scheduler = data.get('scheduler', {}).get('status')
            return scheduler == 'healthy'
        except Exception:
            return False
