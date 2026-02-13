import os
import unittest
import warnings

from secator.airflow.api_client import AirflowAPIClient


AIRFLOW_AVAILABLE = False
try:
	client = AirflowAPIClient()
	AIRFLOW_AVAILABLE = client.is_healthy()
except Exception:
	pass


@unittest.skipUnless(AIRFLOW_AVAILABLE, 'Airflow not running')
class TestAirflowHealth(unittest.TestCase):
	"""Test Airflow API connectivity."""

	@classmethod
	def setUpClass(cls):
		warnings.simplefilter('ignore', category=ResourceWarning)
		cls.client = AirflowAPIClient()

	def test_api_healthy(self):
		self.assertTrue(self.client.is_healthy())

	def test_list_dags(self):
		resp = self.client._request('get', '/dags', params={'limit': 10})
		self.assertEqual(resp.status_code, 200)
		data = resp.json()
		self.assertIn('dags', data)

	def test_secator_dags_registered(self):
		resp = self.client._request('get', '/dags', params={'limit': 200})
		data = resp.json()
		dag_ids = [d['dag_id'] for d in data.get('dags', [])]
		secator_dags = [d for d in dag_ids if d.startswith('secator_')]
		self.assertGreater(len(secator_dags), 0, 'No secator DAGs found')

		# Check for task, workflow, and scan DAGs
		task_dags = [d for d in secator_dags if d.startswith('secator_task_')]
		workflow_dags = [d for d in secator_dags if d.startswith('secator_workflow_')]
		self.assertGreater(len(task_dags), 0, 'No task DAGs found')
		self.assertGreater(len(workflow_dags), 0, 'No workflow DAGs found')


@unittest.skipUnless(AIRFLOW_AVAILABLE, 'Airflow not running')
class TestAirflowTaskExecution(unittest.TestCase):
	"""Test running secator tasks via Airflow."""

	@classmethod
	def setUpClass(cls):
		warnings.simplefilter('ignore', category=ResourceWarning)
		cls.client = AirflowAPIClient()
		# Ensure httpx DAG is unpaused
		cls.client._request(
			'patch', '/dags/secator_task_httpx',
			json={'is_paused': False}
		)

	def test_trigger_and_poll_httpx(self):
		"""Test triggering httpx task and polling to completion."""
		run = self.client.trigger_dag('secator_task_httpx', conf={
			'targets': ['https://example.com'],
			'options': {},
		})
		self.assertIn('dag_run_id', run)
		run_id = run['dag_run_id']

		# Poll until done
		final_state = None
		for status in self.client.poll_dag_run('secator_task_httpx', run_id, interval=2):
			final_state = status.get('state')

		self.assertEqual(final_state, 'success')

	def test_collect_results_httpx(self):
		"""Test collecting structured results from httpx task."""
		run = self.client.trigger_dag('secator_task_httpx', conf={
			'targets': ['https://example.com'],
			'options': {},
		})
		run_id = run['dag_run_id']

		# Wait for completion
		for status in self.client.poll_dag_run('secator_task_httpx', run_id, interval=2):
			if status['state'] in ('success', 'failed'):
				break

		results = self.client.collect_results('secator_task_httpx', run_id)
		self.assertIsInstance(results, list)
		self.assertGreater(len(results), 0)

		# Should have at least a target result
		types = [r.get('_type') for r in results if isinstance(r, dict)]
		self.assertIn('target', types)

	def test_get_task_log(self):
		"""Test retrieving task logs."""
		run = self.client.trigger_dag('secator_task_httpx', conf={
			'targets': ['https://example.com'],
			'options': {},
		})
		run_id = run['dag_run_id']

		for status in self.client.poll_dag_run('secator_task_httpx', run_id, interval=2):
			if status['state'] in ('success', 'failed'):
				break

		log = self.client.get_task_log('secator_task_httpx', run_id, 'httpx')
		self.assertIsInstance(log, str)
		self.assertGreater(len(log), 0)

	def test_xcom_results_key(self):
		"""Test that operator pushes results to the 'results' XCom key."""
		run = self.client.trigger_dag('secator_task_httpx', conf={
			'targets': ['https://example.com'],
			'options': {},
		})
		run_id = run['dag_run_id']

		for status in self.client.poll_dag_run('secator_task_httpx', run_id, interval=2):
			if status['state'] in ('success', 'failed'):
				break

		results = self.client.get_xcom(
			'secator_task_httpx', run_id, 'httpx', key='results'
		)
		self.assertIsNotNone(results)
		self.assertIsInstance(results, list)


@unittest.skipUnless(AIRFLOW_AVAILABLE, 'Airflow not running')
class TestAirflowNmapExecution(unittest.TestCase):
	"""Test nmap task via Airflow (verifies enable_hooks fix)."""

	@classmethod
	def setUpClass(cls):
		warnings.simplefilter('ignore', category=ResourceWarning)
		cls.client = AirflowAPIClient()
		cls.client._request(
			'patch', '/dags/secator_task_nmap',
			json={'is_paused': False}
		)

	def test_nmap_produces_port_results(self):
		"""Verify nmap returns port results (requires enable_hooks=True)."""
		run = self.client.trigger_dag('secator_task_nmap', conf={
			'targets': ['scanme.nmap.org'],
			'options': {},
		})
		run_id = run['dag_run_id']

		for status in self.client.poll_dag_run('secator_task_nmap', run_id, interval=3):
			if status['state'] in ('success', 'failed'):
				break

		self.assertEqual(status['state'], 'success')

		results = self.client.collect_results('secator_task_nmap', run_id)
		types = [r.get('_type') for r in results if isinstance(r, dict)]

		# Must have port results (this fails if enable_hooks=False)
		self.assertIn('port', types, 'No port results — enable_hooks may be False')
		self.assertIn('ip', types)


@unittest.skipUnless(AIRFLOW_AVAILABLE, 'Airflow not running')
class TestAirflowWorkflowExecution(unittest.TestCase):
	"""Test running a workflow via Airflow."""

	@classmethod
	def setUpClass(cls):
		warnings.simplefilter('ignore', category=ResourceWarning)
		cls.client = AirflowAPIClient()
		cls.client._request(
			'patch', '/dags/secator_workflow_host_recon',
			json={'is_paused': False}
		)

	def test_host_recon_workflow(self):
		"""Test host_recon workflow completes and returns results."""
		run = self.client.trigger_dag('secator_workflow_host_recon', conf={
			'targets': ['localhost'],
			'options': {},
		})
		run_id = run['dag_run_id']

		final_state = None
		for status in self.client.poll_dag_run(
			'secator_workflow_host_recon', run_id, interval=3
		):
			final_state = status.get('state')

		self.assertEqual(final_state, 'success')

		# Check task instances
		tis = self.client.get_task_instances(
			'secator_workflow_host_recon', run_id
		)
		self.assertGreater(len(tis), 0)

		states = {ti['task_id']: ti.get('state') for ti in tis}
		# At least one task should have succeeded
		self.assertIn('success', states.values())

	def test_workflow_task_states(self):
		"""Verify task instances have valid Airflow states."""
		run = self.client.trigger_dag('secator_workflow_host_recon', conf={
			'targets': ['localhost'],
			'options': {},
		})
		run_id = run['dag_run_id']

		for status in self.client.poll_dag_run(
			'secator_workflow_host_recon', run_id, interval=3
		):
			if status['state'] in ('success', 'failed'):
				break

		tis = self.client.get_task_instances(
			'secator_workflow_host_recon', run_id
		)
		valid_states = {
			'success', 'failed', 'skipped', 'upstream_failed',
			'queued', 'running', 'scheduled', None,
		}
		for ti in tis:
			self.assertIn(
				ti.get('state'), valid_states,
				f"Unexpected state for {ti['task_id']}: {ti.get('state')}"
			)


@unittest.skipUnless(AIRFLOW_AVAILABLE, 'Airflow not running')
class TestAirflowCLIIntegration(unittest.TestCase):
	"""Test secator CLI with --backend airflow."""

	@classmethod
	def setUpClass(cls):
		warnings.simplefilter('ignore', category=ResourceWarning)
		cls.client = AirflowAPIClient()
		cls.client._request(
			'patch', '/dags/secator_task_httpx',
			json={'is_paused': False}
		)

	def test_cli_task_airflow_backend(self):
		"""Test secator x httpx via CLI with --backend airflow."""
		from secator.runners import Command
		result = Command.execute(
			'secator x httpx https://example.com --backend airflow',
			quiet=True,
		)
		self.assertIsNotNone(result)
