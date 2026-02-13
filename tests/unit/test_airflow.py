import unittest
from unittest.mock import patch, MagicMock


class TestAirflowConfig(unittest.TestCase):
	"""Test Airflow configuration module."""

	def test_default_api_url(self):
		from secator.airflow.config import AIRFLOW_API_URL
		self.assertEqual(AIRFLOW_API_URL, 'http://localhost:8080/api/v2')

	def test_default_username(self):
		from secator.airflow.config import AIRFLOW_USERNAME
		self.assertEqual(AIRFLOW_USERNAME, 'admin')

	@patch('builtins.open', side_effect=FileNotFoundError)
	def test_password_fallback_when_no_file(self, mock_open):
		from secator.airflow.config import _read_standalone_password
		password = _read_standalone_password()
		self.assertEqual(password, 'admin')

	@patch('builtins.open')
	def test_password_read_from_file(self, mock_open):
		mock_open.return_value.__enter__ = lambda s: s
		mock_open.return_value.__exit__ = MagicMock(return_value=False)
		mock_open.return_value.read = lambda: '{"admin": "secret123"}'
		from secator.airflow.config import _read_standalone_password
		password = _read_standalone_password()
		self.assertEqual(password, 'secret123')

	def test_get_poll_frequency(self):
		from secator.airflow.config import get_poll_frequency
		freq = get_poll_frequency()
		self.assertIsInstance(freq, (int, float))
		self.assertGreater(freq, 0)


class TestAirflowAPIClient(unittest.TestCase):
	"""Test AirflowAPIClient methods."""

	def _make_client(self):
		from secator.airflow.api_client import AirflowAPIClient
		return AirflowAPIClient(
			base_url='http://localhost:8080/api/v2',
			username='admin',
			password='test',
		)

	def test_init(self):
		client = self._make_client()
		self.assertEqual(client.base_url, 'http://localhost:8080/api/v2')
		self.assertEqual(client.username, 'admin')
		self.assertEqual(client.password, 'test')
		self.assertIsNone(client._token)

	def test_get_auth_base_url_strips_api_v2(self):
		client = self._make_client()
		self.assertEqual(
			client._get_auth_base_url(),
			'http://localhost:8080'
		)

	def test_get_auth_base_url_strips_api_v1(self):
		from secator.airflow.api_client import AirflowAPIClient
		client = AirflowAPIClient(base_url='http://localhost:8080/api/v1')
		self.assertEqual(
			client._get_auth_base_url(),
			'http://localhost:8080'
		)

	def test_get_auth_base_url_no_suffix(self):
		from secator.airflow.api_client import AirflowAPIClient
		client = AirflowAPIClient(base_url='http://localhost:8080')
		self.assertEqual(
			client._get_auth_base_url(),
			'http://localhost:8080'
		)

	@patch('requests.post')
	def test_authenticate_success(self, mock_post):
		mock_resp = MagicMock()
		mock_resp.json.return_value = {'access_token': 'tok123'}
		mock_resp.raise_for_status = MagicMock()
		mock_post.return_value = mock_resp

		client = self._make_client()
		client._authenticate()

		self.assertEqual(client._token, 'tok123')
		self.assertEqual(
			client.session.headers['Authorization'],
			'Bearer tok123'
		)
		mock_post.assert_called_once_with(
			'http://localhost:8080/auth/token',
			json={'username': 'admin', 'password': 'test'},
		)

	@patch('requests.post')
	def test_authenticate_failure(self, mock_post):
		from requests.exceptions import HTTPError
		mock_resp = MagicMock()
		mock_resp.raise_for_status.side_effect = HTTPError('401')
		mock_post.return_value = mock_resp

		client = self._make_client()
		with self.assertRaises(HTTPError):
			client._authenticate()

	@patch.object(
		__import__('secator.airflow.api_client', fromlist=['AirflowAPIClient']).AirflowAPIClient,
		'_ensure_auth'
	)
	def test_trigger_dag(self, mock_auth):
		client = self._make_client()
		mock_resp = MagicMock()
		mock_resp.status_code = 200
		mock_resp.raise_for_status = MagicMock()
		mock_resp.json.return_value = {
			'dag_run_id': 'run_123',
			'dag_id': 'secator_task_nmap',
			'state': 'queued',
		}
		client.session.post = MagicMock(return_value=mock_resp)

		result = client.trigger_dag('secator_task_nmap', conf={
			'targets': ['localhost'],
			'options': {},
		})

		self.assertEqual(result['dag_run_id'], 'run_123')
		self.assertEqual(result['state'], 'queued')
		client.session.post.assert_called_once()
		call_args = client.session.post.call_args
		self.assertIn('/dags/secator_task_nmap/dagRuns', call_args[0][0])

	@patch.object(
		__import__('secator.airflow.api_client', fromlist=['AirflowAPIClient']).AirflowAPIClient,
		'_ensure_auth'
	)
	def test_get_dag_run(self, mock_auth):
		client = self._make_client()
		mock_resp = MagicMock()
		mock_resp.status_code = 200
		mock_resp.raise_for_status = MagicMock()
		mock_resp.json.return_value = {
			'state': 'success',
			'dag_id': 'secator_task_nmap',
			'dag_run_id': 'run_123',
		}
		client.session.get = MagicMock(return_value=mock_resp)

		result = client.get_dag_run('secator_task_nmap', 'run_123')
		self.assertEqual(result['state'], 'success')

	@patch.object(
		__import__('secator.airflow.api_client', fromlist=['AirflowAPIClient']).AirflowAPIClient,
		'_ensure_auth'
	)
	def test_is_healthy_true(self, mock_auth):
		client = self._make_client()
		mock_resp = MagicMock()
		mock_resp.status_code = 200
		mock_resp.raise_for_status = MagicMock()
		mock_resp.json.return_value = {
			'scheduler': {'status': 'healthy'},
			'metadatabase': {'status': 'healthy'},
		}
		client.session.get = MagicMock(return_value=mock_resp)

		self.assertTrue(client.is_healthy())

	@patch.object(
		__import__('secator.airflow.api_client', fromlist=['AirflowAPIClient']).AirflowAPIClient,
		'_ensure_auth'
	)
	def test_is_healthy_false(self, mock_auth):
		client = self._make_client()
		mock_resp = MagicMock()
		mock_resp.status_code = 200
		mock_resp.raise_for_status = MagicMock()
		mock_resp.json.return_value = {
			'scheduler': {'status': 'unhealthy'},
		}
		client.session.get = MagicMock(return_value=mock_resp)

		self.assertFalse(client.is_healthy())

	def test_is_healthy_connection_error(self):
		client = self._make_client()
		client._token = 'fake'
		client.session.get = MagicMock(side_effect=ConnectionError)

		self.assertFalse(client.is_healthy())


class TestAirflowUtils(unittest.TestCase):
	"""Test Airflow utility functions."""

	def test_serialize_results(self):
		from secator.airflow.utils import serialize_results
		from secator.output_types import Target

		target = Target(name='example.com', type='host', _source='test')
		results = serialize_results([target, {'raw': 'dict'}])
		self.assertEqual(len(results), 2)
		self.assertIsInstance(results[0], dict)
		self.assertEqual(results[0]['name'], 'example.com')
		self.assertEqual(results[1], {'raw': 'dict'})

	def test_deserialize_results(self):
		from secator.airflow.utils import deserialize_results
		from secator.output_types import Target

		raw = [
			{'name': 'example.com', 'type': 'host', '_type': 'target', '_source': 'test'},
			{'unknown': 'data'},
		]
		results = deserialize_results(raw)
		self.assertEqual(len(results), 2)
		self.assertIsInstance(results[0], Target)
		self.assertEqual(results[0].name, 'example.com')
		self.assertIsInstance(results[1], dict)

	def test_deduplicate_results(self):
		from secator.airflow.utils import deduplicate_results

		results = [
			{'_uuid': 'aaa', 'name': 'first'},
			{'_uuid': 'bbb', 'name': 'second'},
			{'_uuid': 'aaa', 'name': 'first-dup'},
		]
		deduped = deduplicate_results(results)
		self.assertEqual(len(deduped), 2)
		self.assertEqual(deduped[0]['name'], 'first')
		self.assertEqual(deduped[1]['name'], 'second')

	def test_flatten_results(self):
		from secator.airflow.utils import flatten_results

		nested = [
			[{'name': 'a'}, {'name': 'b'}],
			{'name': 'c'},
			[{'name': 'd'}],
		]
		flat = flatten_results(nested)
		self.assertEqual(len(flat), 4)
		self.assertEqual(flat[0]['name'], 'a')
		self.assertEqual(flat[2]['name'], 'c')

	def test_flatten_results_empty(self):
		from secator.airflow.utils import flatten_results
		self.assertEqual(flatten_results([]), [])
		self.assertEqual(flatten_results(None), [])

	def test_extract_targets_shortcut(self):
		from secator.airflow.utils import extract_targets

		results = [
			{'_type': 'subdomain', 'host': 'sub.example.com'},
			{'_type': 'subdomain', 'host': 'other.example.com'},
			{'_type': 'url', 'url': 'http://example.com'},
		]
		targets = extract_targets(results, ['subdomain.host'])
		self.assertEqual(len(targets), 2)
		self.assertIn('sub.example.com', targets)
		self.assertIn('other.example.com', targets)

	def test_extract_targets_dict_format(self):
		from secator.airflow.utils import extract_targets

		results = [
			{'_type': 'port', 'host': '10.0.0.1', 'port': 80},
			{'_type': 'port', 'host': '10.0.0.2', 'port': 443},
		]
		targets = extract_targets(results, [
			{'type': 'port', 'field': 'host'}
		])
		self.assertEqual(len(targets), 2)
		self.assertIn('10.0.0.1', targets)

	def test_extract_targets_with_condition(self):
		from secator.airflow.utils import extract_targets

		results = [
			{'_type': 'port', 'host': '10.0.0.1', 'port': 22},
			{'_type': 'port', 'host': '10.0.0.2', 'port': 80},
		]
		targets = extract_targets(results, [
			{'type': 'port', 'field': 'host', 'condition': 'port.port == 22'}
		])
		self.assertEqual(len(targets), 1)
		self.assertEqual(targets[0], '10.0.0.1')

	def test_extract_targets_empty_extractors(self):
		from secator.airflow.utils import extract_targets
		self.assertEqual(extract_targets([{'_type': 'url'}], []), [])

	def test_get_finding_counts(self):
		from secator.airflow.utils import get_finding_counts

		results = [
			{'_type': 'port'},
			{'_type': 'port'},
			{'_type': 'vulnerability'},
			{'_type': 'url'},
			{'_type': 'stat'},  # not a finding type
		]
		counts = get_finding_counts(results)
		self.assertEqual(counts.get('port'), 2)
		self.assertEqual(counts.get('vulnerability'), 1)
		self.assertEqual(counts.get('url'), 1)
		self.assertNotIn('stat', counts)


class TestDAGFactory(unittest.TestCase):
	"""Test Airflow DAG generation from secator configs."""

	def test_sanitize_id(self):
		from secator.airflow.dag_factory.workflow_dag import _sanitize_id
		self.assertEqual(_sanitize_id('nmap/light'), 'nmap_light')
		self.assertEqual(_sanitize_id('nuclei.network'), 'nuclei_network')
		self.assertEqual(_sanitize_id('my-task'), 'my_task')
		self.assertEqual(_sanitize_id('simple'), 'simple')

	def test_make_task_node(self):
		from secator.airflow.dag_factory.workflow_dag import _make_task_node

		node = _make_task_node('nmap/light', {
			'description': 'Find open ports',
			'if': 'not opts.passive',
			'tcp_syn_stealth': True,
		})
		self.assertEqual(node['type'], 'task')
		self.assertEqual(node['name'], 'nmap')
		self.assertEqual(node['alias'], 'light')
		self.assertEqual(node['node_id'], 'nmap/light')
		self.assertEqual(node['description'], 'Find open ports')
		self.assertEqual(node['condition'], 'not opts.passive')
		self.assertIn('tcp_syn_stealth', node['opts'])
		self.assertNotIn('description', node['opts'])
		self.assertNotIn('if', node['opts'])

	def test_make_task_node_no_alias(self):
		from secator.airflow.dag_factory.workflow_dag import _make_task_node

		node = _make_task_node('httpx', {'description': 'Probe HTTP'})
		self.assertEqual(node['name'], 'httpx')
		self.assertIsNone(node['alias'])
		self.assertEqual(node['node_id'], 'httpx')

	def test_parse_task_nodes(self):
		from secator.airflow.dag_factory.workflow_dag import _parse_task_nodes

		tasks_config = {
			'httpx': {'description': 'Probe HTTP'},
			'_group/parallel': {
				'nmap/light': {'description': 'Fast scan'},
				'naabu': {'description': 'Port scan'},
			},
			'nuclei': {'description': 'Vuln scan'},
		}
		nodes = _parse_task_nodes(tasks_config)
		self.assertEqual(len(nodes), 3)
		self.assertEqual(nodes[0]['type'], 'task')
		self.assertEqual(nodes[0]['name'], 'httpx')
		self.assertEqual(nodes[1]['type'], 'group')
		self.assertEqual(nodes[1]['name'], 'parallel')
		self.assertEqual(len(nodes[1]['children']), 2)
		self.assertEqual(nodes[2]['type'], 'task')
		self.assertEqual(nodes[2]['name'], 'nuclei')

	def test_generate_all_task_dags(self):
		from secator.airflow.dag_factory.task_dag import generate_all_task_dags
		dags = generate_all_task_dags()
		self.assertGreater(len(dags), 0)
		for dag_id in dags:
			self.assertTrue(dag_id.startswith('secator_task_'))

	def test_generate_all_workflow_dags(self):
		from secator.airflow.dag_factory.workflow_dag import generate_all_workflow_dags
		dags = generate_all_workflow_dags()
		self.assertGreater(len(dags), 0)
		for dag_id, dag in dags.items():
			self.assertTrue(dag_id.startswith('secator_workflow_'))
			self.assertGreater(len(dag.tasks), 0)

	def test_no_duplicate_task_ids(self):
		"""Verify no workflow DAG has duplicate task IDs."""
		from secator.airflow.dag_factory.workflow_dag import generate_all_workflow_dags
		dags = generate_all_workflow_dags()
		for dag_id, dag in dags.items():
			task_ids = [t.task_id for t in dag.tasks]
			self.assertEqual(
				len(task_ids), len(set(task_ids)),
				f'Duplicate task IDs in {dag_id}: {task_ids}'
			)

	def test_host_recon_dag_structure(self):
		"""Test that host_recon DAG has expected tasks."""
		from secator.airflow.dag_factory.workflow_dag import generate_all_workflow_dags
		dags = generate_all_workflow_dags()
		dag = dags.get('secator_workflow_host_recon')
		self.assertIsNotNone(dag)
		task_ids = [t.task_id for t in dag.tasks]
		# Should contain nmap-related tasks
		nmap_tasks = [t for t in task_ids if 'nmap' in t]
		self.assertGreater(len(nmap_tasks), 0)


class TestAirflowStateMapping(unittest.TestCase):
	"""Test Airflow state to secator state mapping."""

	def test_state_colors_include_skipped(self):
		from secator.definitions import STATE_COLORS
		self.assertIn('SKIPPED', STATE_COLORS)
		self.assertIn('PENDING', STATE_COLORS)
		self.assertIn('RUNNING', STATE_COLORS)
		self.assertIn('SUCCESS', STATE_COLORS)
		self.assertIn('FAILURE', STATE_COLORS)
		self.assertIn('REVOKED', STATE_COLORS)


class TestSecatorTaskOperator(unittest.TestCase):
	"""Test the SecatorTaskOperator."""

	def test_operator_init(self):
		from secator.airflow.operators.secator_task import SecatorTaskOperator
		op = SecatorTaskOperator(
			task_id='test_nmap',
			task_name='nmap',
			targets=['localhost'],
			opts={'ports': '80,443'},
			dag=None,
		)
		self.assertEqual(op.task_name, 'nmap')
		self.assertEqual(op.targets, ['localhost'])
		self.assertEqual(op.opts, {'ports': '80,443'})

	def test_operator_enable_hooks_true(self):
		"""Verify operator sets enable_hooks=True for tool hooks to work."""
		from secator.airflow.operators.secator_task import SecatorTaskOperator
		op = SecatorTaskOperator(
			task_id='test_nmap',
			task_name='nmap',
			dag=None,
		)
		# Simulate what execute() does via _build_run_opts
		mock_context = {
			'ti': MagicMock(),
			'dag_run': MagicMock(conf={}),
		}
		run_opts = op._build_run_opts(mock_context)
		self.assertTrue(run_opts['enable_hooks'])

	def test_operator_template_fields(self):
		from secator.airflow.operators.secator_task import SecatorTaskOperator
		self.assertIn('targets', SecatorTaskOperator.template_fields)
		self.assertIn('opts', SecatorTaskOperator.template_fields)
		self.assertIn('context', SecatorTaskOperator.template_fields)


class TestSecatorBridgeOperator(unittest.TestCase):
	"""Test the SecatorBridgeOperator."""

	def test_bridge_operator_init(self):
		from secator.airflow.operators.secator_bridge import SecatorBridgeOperator
		op = SecatorBridgeOperator(
			task_id='bridge_test',
			dag=None,
		)
		self.assertEqual(op.task_id, 'bridge_test')
