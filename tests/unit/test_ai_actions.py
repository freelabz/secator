# tests/unit/test_ai_actions.py
"""Tests for AI action handlers - shell execution, queries, decryption."""

import unittest
from unittest.mock import patch, MagicMock

from secator.definitions import ADDONS_ENABLED

if ADDONS_ENABLED['ai']:
	from secator.ai.actions import (
		ActionContext, dispatch_action, _handle_follow_up, _handle_shell,
		_handle_query, _handle_add_finding, _run_runner, _decrypt_dict,
		_build_hooks_from_context, _coerce_finding_fields
	)
	from secator.output_types import Ai, Error, Info, Warning, Vulnerability, Url


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestDecryptDict(unittest.TestCase):
	"""Tests for _decrypt_dict recursive decryption."""

	def test_decrypt_string_values(self):
		encryptor = MagicMock()
		encryptor.decrypt.side_effect = lambda x: x.upper()

		result = _decrypt_dict({'host': 'example.com', 'port': '443'}, encryptor)

		self.assertEqual(result['host'], 'EXAMPLE.COM')
		self.assertEqual(result['port'], '443')

	def test_decrypt_nested_dict(self):
		encryptor = MagicMock()
		encryptor.decrypt.side_effect = lambda x: x.upper()

		result = _decrypt_dict({'outer': {'inner': 'value'}}, encryptor)

		self.assertEqual(result['outer']['inner'], 'VALUE')

	def test_decrypt_list_values(self):
		encryptor = MagicMock()
		encryptor.decrypt.side_effect = lambda x: x.upper()

		result = _decrypt_dict(
			{
				'hosts': ['a.com', 'b.com'],
			},
			encryptor,
		)

		self.assertEqual(result['hosts'], ['A.COM', 'B.COM'])

	def test_decrypt_mixed_list(self):
		encryptor = MagicMock()
		encryptor.decrypt.side_effect = lambda x: x.upper()

		result = _decrypt_dict(
			{
				'items': ['text', 42, {'key': 'val'}],
			},
			encryptor,
		)

		self.assertEqual(result['items'][0], 'TEXT')
		self.assertEqual(result['items'][1], 42)
		self.assertEqual(result['items'][2]['key'], 'VAL')

	def test_decrypt_non_string_values(self):
		encryptor = MagicMock()

		result = _decrypt_dict(
			{
				'count': 5,
				'active': True,
				'score': 3.14,
			},
			encryptor,
		)

		self.assertEqual(result['count'], 5)
		self.assertEqual(result['active'], True)
		self.assertEqual(result['score'], 3.14)
		encryptor.decrypt.assert_not_called()


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestHandleFollowUp(unittest.TestCase):
	"""Tests for the _handle_follow_up action handler."""

	def test_follow_up_with_reason(self):
		ctx = ActionContext(targets=['t.com'], model='m')
		results = list(_handle_follow_up({'action': 'follow_up', 'reason': 'All scanned'}, ctx))

		self.assertEqual(len(results), 1)
		self.assertIsInstance(results[0], Ai)
		self.assertEqual(results[0].ai_type, 'follow_up')
		self.assertEqual(results[0].content, 'All scanned')
		self.assertEqual(results[0].extra_data['choices'], [])

	def test_follow_up_default_reason(self):
		ctx = ActionContext(targets=['t.com'], model='m')
		results = list(_handle_follow_up({'action': 'follow_up'}, ctx))

		self.assertEqual(results[0].content, 'completed')
		self.assertEqual(results[0].extra_data['choices'], [])

	def test_follow_up_with_choices(self):
		ctx = ActionContext(targets=['t.com'], model='m')
		results = list(
			_handle_follow_up(
				{
					'action': 'follow_up',
					'reason': 'What next?',
					'choices': ['Scan deeper', 'Try SQL injection'],
				},
				ctx,
			)
		)

		self.assertEqual(len(results), 1)
		self.assertEqual(results[0].ai_type, 'follow_up')
		self.assertEqual(results[0].content, 'What next?')
		self.assertEqual(results[0].extra_data['choices'], ['Scan deeper', 'Try SQL injection'])
		# Choices must also land on the top-level `choices` field (what the web UI reads),
		# not only in extra_data — otherwise the persisted follow-up doc renders no buttons.
		self.assertEqual(results[0].choices, ['Scan deeper', 'Try SQL injection'])


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestHandleShell(unittest.TestCase):
	"""Tests for the _handle_shell action handler."""

	def test_shell_dry_run(self):
		ctx = ActionContext(targets=['t.com'], model='m', dry_run=True)
		results = list(_handle_shell({'action': 'shell', 'command': 'whoami'}, ctx))

		self.assertEqual(len(results), 1)
		self.assertIsInstance(results[0], Info)
		self.assertIn('DRY RUN', results[0].message)
		self.assertIn('whoami', results[0].message)

	@patch('secator.ai.actions.subprocess.run')
	def test_shell_execution(self, mock_run):
		mock_run.return_value = MagicMock(stdout='root\n', stderr='')
		ctx = ActionContext(targets=['t.com'], model='m')

		results = list(_handle_shell({'action': 'shell', 'command': 'whoami'}, ctx))

		self.assertEqual(len(results), 2)
		# First: the command being run
		self.assertIsInstance(results[0], Ai)
		self.assertEqual(results[0].ai_type, 'shell')
		self.assertEqual(results[0].content, 'whoami')
		# Second: the output
		self.assertIsInstance(results[1], Ai)
		self.assertEqual(results[1].ai_type, 'shell_output')
		self.assertIn('root', results[1].content)

	@patch('secator.ai.actions.subprocess.run')
	def test_shell_stderr(self, mock_run):
		mock_run.return_value = MagicMock(stdout='', stderr='error msg')
		ctx = ActionContext(targets=['t.com'], model='m')

		results = list(_handle_shell({'action': 'shell', 'command': 'bad'}, ctx))

		self.assertEqual(results[1].content, 'error msg')

	@patch('secator.ai.actions.subprocess.run')
	def test_shell_no_output(self, mock_run):
		mock_run.return_value = MagicMock(stdout='', stderr='')
		ctx = ActionContext(targets=['t.com'], model='m')

		results = list(_handle_shell({'action': 'shell', 'command': 'true'}, ctx))

		self.assertEqual(results[1].content, '(no output)')

	@patch('secator.ai.actions.subprocess.run')
	def test_shell_exception(self, mock_run):
		mock_run.side_effect = Exception('Command timed out')
		ctx = ActionContext(targets=['t.com'], model='m')

		results = list(_handle_shell({'action': 'shell', 'command': 'slow'}, ctx))

		# shell Ai + Error
		self.assertEqual(len(results), 2)
		self.assertIsInstance(results[1], Error)
		self.assertIn('failed', results[1].message)

	def test_shell_decrypts_command(self):
		encryptor = MagicMock()
		encryptor.decrypt.side_effect = lambda x: x.replace('ENCRYPTED', 'real-host')
		ctx = ActionContext(targets=['t.com'], model='m', encryptor=encryptor, dry_run=True)

		results = list(_handle_shell({'action': 'shell', 'command': 'nmap ENCRYPTED'}, ctx))

		self.assertIn('real-host', results[0].message)
		encryptor.decrypt.assert_called_once_with('nmap ENCRYPTED')


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestHandleQuery(unittest.TestCase):
	"""Tests for the _handle_query action handler."""

	def test_query_no_workspace(self):
		ctx = ActionContext(targets=['t.com'], model='m', context={})
		results = list(_handle_query({'action': 'query', 'query': {}}, ctx))

		self.assertEqual(len(results), 1)
		self.assertIsInstance(results[0], Warning)
		self.assertIn('workspace', results[0].message.lower())

	def test_query_current_scope_no_workspace_ok(self):
		"""Scope='current' should work without workspace_id."""
		ctx = ActionContext(targets=['t.com'], model='m', context={}, scope='current', results=[{'host': 'a.com', 'port': 80}])

		with patch.object(ctx, 'get_query_engine') as mock_get_engine:
			mock_engine = MagicMock()
			mock_engine.search.return_value = [{'host': 'a.com', 'port': 80, '_context': {}}]
			mock_get_engine.return_value = mock_engine

			results = list(_handle_query({'action': 'query', 'query': {'host': 'a.com'}}, ctx))

		# Should have Ai + result dict (no warning)
		ai_results = [r for r in results if isinstance(r, Ai)]
		self.assertEqual(len(ai_results), 1)
		self.assertEqual(ai_results[0].ai_type, 'query')

	@patch('secator.ai.actions.ActionContext.get_query_engine')
	def test_query_success(self, mock_get_engine):
		mock_engine = MagicMock()
		mock_engine.search.return_value = [
			{'host': 'a.com', 'port': 80, '_type': 'port', '_context': {}},
			{'host': 'b.com', 'port': 443, '_type': 'port', '_context': {}},
		]
		mock_get_engine.return_value = mock_engine
		ctx = ActionContext(targets=['t.com'], model='m', context={'workspace_id': 'ws1'})

		results = list(_handle_query({'action': 'query', 'query': {'port': 80}, 'limit': 10}, ctx))

		# Ai header + 2 result dicts
		ai_results = [r for r in results if isinstance(r, Ai)]
		self.assertEqual(len(ai_results), 1)
		self.assertEqual(ai_results[0].extra_data['results'], 2)
		mock_engine.search.assert_called_once_with({'port': 80}, limit=10)

		# Query results are marked observation-only so the runner doesn't re-report them.
		result_dicts = [r for r in results if isinstance(r, dict)]
		self.assertEqual(len(result_dicts), 2)
		for r in result_dicts:
			self.assertTrue(r['_context'].get('ai_query_result'))

	@patch('secator.ai.actions.ActionContext.get_query_engine')
	def test_query_failure(self, mock_get_engine):
		mock_engine = MagicMock()
		mock_engine.search.side_effect = Exception('DB error')
		mock_get_engine.return_value = mock_engine
		ctx = ActionContext(targets=['t.com'], model='m', context={'workspace_id': 'ws1'})

		results = list(_handle_query({'action': 'query', 'query': {}}, ctx))

		errors = [r for r in results if isinstance(r, Error)]
		self.assertEqual(len(errors), 1)

	def test_query_decrypts_filter(self):
		encryptor = MagicMock()
		encryptor.decrypt.side_effect = lambda x: x.replace('ENC_', '')
		ctx = ActionContext(targets=['t.com'], model='m', context={'workspace_id': 'ws1'}, encryptor=encryptor)

		with patch.object(ctx, 'get_query_engine') as mock_get_engine:
			mock_engine = MagicMock()
			mock_engine.search.return_value = []
			mock_get_engine.return_value = mock_engine

			list(_handle_query({'action': 'query', 'query': {'host': 'ENC_example.com'}}, ctx))

		# Verify the decrypted value was used
		mock_engine.search.assert_called_once()
		call_args = mock_engine.search.call_args[0][0]
		self.assertEqual(call_args['host'], 'example.com')


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestRunRunner(unittest.TestCase):
	"""Tests for the _run_runner function."""

	def test_run_runner_dry_run_task(self):
		ctx = ActionContext(targets=['t.com'], model='m', dry_run=True)
		action = {'action': 'task', 'name': 'nmap', 'targets': ['192.168.1.1']}

		results = list(_run_runner(action, ctx, 'task'))

		self.assertEqual(len(results), 1)
		self.assertIsInstance(results[0], Info)
		self.assertIn('DRY RUN', results[0].message)
		self.assertIn('nmap', results[0].message)

	def test_run_runner_dry_run_workflow(self):
		ctx = ActionContext(targets=['t.com'], model='m', dry_run=True)
		action = {'action': 'workflow', 'name': 'host_recon', 'targets': ['t.com']}

		results = list(_run_runner(action, ctx, 'workflow'))

		self.assertIn('DRY RUN', results[0].message)
		self.assertIn('host_recon', results[0].message)

	def test_run_runner_decrypts_targets(self):
		encryptor = MagicMock()
		encryptor.decrypt.side_effect = lambda x: x.replace('ENC_', '')
		ctx = ActionContext(targets=['t.com'], model='m', encryptor=encryptor, dry_run=True)
		action = {'action': 'task', 'name': 'nmap', 'targets': ['ENC_10.0.0.1']}

		results = list(_run_runner(action, ctx, 'task'))

		self.assertIn('10.0.0.1', results[0].message)

	def test_run_runner_uses_ctx_targets_as_default(self):
		ctx = ActionContext(targets=['default.com'], model='m', dry_run=True)
		action = {'action': 'task', 'name': 'nmap'}  # no targets in action

		results = list(_run_runner(action, ctx, 'task'))

		self.assertIn('default.com', results[0].message)

	@patch('secator.ai.actions.TemplateLoader')
	@patch('secator.ai.actions.Task')
	@patch('secator.ai.actions._build_hooks_from_context')
	def test_run_runner_propagates_hooks_and_emits_runner_id(self, mock_build_hooks, mock_task_cls, _mock_tpl):
		"""Sub-runner must receive driver hooks (so its results persist) and the
		emitted action Ai must carry the created runner's id + type for the UI."""
		sentinel_hooks = {'fake': ['hook']}
		mock_build_hooks.return_value = sentinel_hooks

		# Fake runner: an iterable whose id is populated (mimics on_init stamping it)
		mock_runner = MagicMock()
		mock_runner.id = 'runner123'
		mock_runner.reports_folder = None
		mock_runner.__iter__.return_value = iter([])
		mock_task_cls.return_value = mock_runner

		ctx = ActionContext(
			targets=['t.com'], model='m',
			context={'workspace_id': 'ws1', 'drivers': ['mongodb']},
		)
		action = {'action': 'task', 'name': 'nmap', 'targets': ['10.0.0.1']}

		results = list(_run_runner(action, ctx, 'task'))

		# Runner constructed with hooks= from the context drivers
		_, kwargs = mock_task_cls.call_args
		self.assertEqual(kwargs.get('hooks'), sentinel_hooks)
		self.assertEqual(kwargs.get('context', {}).get('workspace_id'), 'ws1')

		# Action Ai item carries runner_id + runner_type
		ai_items = [r for r in results if isinstance(r, Ai) and r.ai_type == 'task']
		self.assertEqual(len(ai_items), 1)
		self.assertEqual(ai_items[0].extra_data.get('runner_id'), 'runner123')
		self.assertEqual(ai_items[0].extra_data.get('runner_type'), 'task')

	@patch('secator.ai.actions.TemplateLoader')
	@patch('secator.ai.actions.Task')
	@patch('secator.ai.actions._build_hooks_from_context')
	def test_run_runner_propagates_session_id(self, mock_build_hooks, mock_task_cls, _mock_tpl):
		"""The dispatched sub-runner's context must carry the ai task's session_id
		(the conversation id) so its persisted runner doc is queryable by the
		conversation. session_id may be derived (not already in ctx.context), so
		it must be stamped from ctx.session_id."""
		mock_build_hooks.return_value = {}
		mock_runner = MagicMock()
		mock_runner.id = 'runner123'
		mock_runner.reports_folder = None
		mock_runner.__iter__.return_value = iter([])
		mock_task_cls.return_value = mock_runner

		# session_id lives on the ActionContext but NOT in context (it is derived)
		ctx = ActionContext(
			targets=['t.com'], model='m',
			context={'workspace_id': 'ws1', 'drivers': ['mongodb']},
			session_id='conv-abc-123',
		)
		action = {'action': 'task', 'name': 'nmap', 'targets': ['10.0.0.1']}

		list(_run_runner(action, ctx, 'task'))

		_, kwargs = mock_task_cls.call_args
		sub_context = kwargs.get('context', {})
		self.assertEqual(sub_context.get('session_id'), 'conv-abc-123')
		self.assertEqual(sub_context.get('workspace_id'), 'ws1')

	@patch('secator.ai.actions.TemplateLoader')
	@patch('secator.ai.actions.Task')
	@patch('secator.ai.actions._build_hooks_from_context')
	def test_run_runner_preserves_existing_session_id(self, mock_build_hooks, mock_task_cls, _mock_tpl):
		"""A session_id already present in ctx.context must not be overwritten."""
		mock_build_hooks.return_value = {}
		mock_runner = MagicMock()
		mock_runner.id = 'runner123'
		mock_runner.reports_folder = None
		mock_runner.__iter__.return_value = iter([])
		mock_task_cls.return_value = mock_runner

		ctx = ActionContext(
			targets=['t.com'], model='m',
			context={'workspace_id': 'ws1', 'session_id': 'from-context'},
			session_id='from-ctx-field',
		)
		action = {'action': 'task', 'name': 'nmap', 'targets': ['10.0.0.1']}

		list(_run_runner(action, ctx, 'task'))

		_, kwargs = mock_task_cls.call_args
		self.assertEqual(kwargs.get('context', {}).get('session_id'), 'from-context')


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestBuildHooksFromContext(unittest.TestCase):
	"""Tests for _build_hooks_from_context (driver name -> hooks dict)."""

	def test_no_drivers_returns_empty(self):
		self.assertEqual(_build_hooks_from_context({}), {})
		self.assertEqual(_build_hooks_from_context({'drivers': []}), {})

	@patch('secator.loader.get_available_drivers')
	@patch('secator.loader.order_drivers')
	@patch('secator.loader.discover_external_drivers')
	@patch('secator.utils.import_dynamic')
	def test_builds_hooks_from_driver_names(self, mock_import, _disc, mock_order, mock_avail):
		from secator.runners import Task
		mock_order.side_effect = lambda d: d
		mock_avail.return_value = ['mongodb', 'api']
		mongo_hooks = {Task: {'on_init': ['update_runner']}}
		mock_import.return_value = mongo_hooks

		hooks = _build_hooks_from_context({'drivers': ['mongodb']})

		mock_import.assert_called_once_with('secator.hooks.mongodb', 'HOOKS')
		self.assertIn(Task, hooks)
		self.assertIn('on_init', hooks[Task])

	@patch('secator.loader.get_available_drivers')
	@patch('secator.loader.order_drivers')
	@patch('secator.loader.discover_external_drivers')
	@patch('secator.utils.import_dynamic')
	def test_skips_unsupported_driver(self, mock_import, _disc, mock_order, mock_avail):
		mock_order.side_effect = lambda d: d
		mock_avail.return_value = ['mongodb']
		hooks = _build_hooks_from_context({'drivers': ['bogus']})
		self.assertEqual(hooks, {})
		mock_import.assert_not_called()


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestGetQueryEngine(unittest.TestCase):
	"""Tests for ActionContext.get_query_engine caching and backend selection."""

	@patch('secator.query.QueryEngine')
	def test_caching(self, mock_qe_cls):
		"""Same engine instance returned on second call."""
		mock_engine = MagicMock()
		mock_qe_cls.return_value = mock_engine

		ctx = ActionContext(targets=['t.com'], model='m', context={'workspace_id': 'ws1', 'drivers': ['mongodb']})
		engine1 = ctx.get_query_engine()
		engine2 = ctx.get_query_engine()

		self.assertIs(engine1, engine2)
		mock_qe_cls.assert_called_once()

	# -- scope=current: always JsonBackend with in-memory results --

	def test_current_scope_uses_json_backend(self):
		"""scope=current always selects JsonBackend, even if drivers has mongodb."""
		from secator.query.json import JsonBackend

		results = [{'_type': 'url', 'url': 'http://a.com'}]
		ctx = ActionContext(
			targets=['t.com'],
			model='m',
			context={'workspace_id': 'ws1', 'drivers': ['mongodb']},
			scope='current',
			results=results,
		)
		engine = ctx.get_query_engine()

		self.assertIsInstance(engine.backend, JsonBackend)

	def test_current_scope_passes_results(self):
		"""scope=current passes results to the backend."""
		results = [{'_type': 'url', 'url': 'http://a.com'}]
		ctx = ActionContext(
			targets=['t.com'],
			model='m',
			context={'workspace_id': 'ws1'},
			scope='current',
			results=results,
		)
		engine = ctx.get_query_engine()

		self.assertIs(engine.backend._results, results)

	def test_current_scope_does_not_pass_drivers(self):
		"""scope=current context should not contain drivers."""
		ctx = ActionContext(
			targets=['t.com'],
			model='m',
			context={'workspace_id': 'ws1', 'drivers': ['mongodb']},
			scope='current',
			results=[],
		)
		engine = ctx.get_query_engine()

		self.assertEqual(engine.context.get('drivers', []), [])

	def test_current_scope_search_queries_in_memory(self):
		"""scope=current queries against in-memory results."""
		results = [
			{'_type': 'vulnerability', 'name': 'SQLi', 'severity': 'critical'},
			{'_type': 'url', 'url': 'http://a.com'},
			{'_type': 'vulnerability', 'name': 'XSS', 'severity': 'low'},
		]
		ctx = ActionContext(
			targets=['t.com'],
			model='m',
			context={},
			scope='current',
			results=results,
		)
		engine = ctx.get_query_engine()
		found = engine.search({'_type': 'vulnerability'})

		self.assertEqual(len(found), 2)
		self.assertTrue(all(r['_type'] == 'vulnerability' for r in found))

	# -- scope=workspace + json (no drivers) --

	def test_workspace_scope_json_backend(self):
		"""scope=workspace with no drivers selects JsonBackend."""
		from secator.query.json import JsonBackend

		ctx = ActionContext(
			targets=['t.com'],
			model='m',
			context={'workspace_id': 'ws1'},
		)
		engine = ctx.get_query_engine()

		self.assertIsInstance(engine.backend, JsonBackend)

	def test_workspace_scope_json_no_results_preloaded(self):
		"""scope=workspace JsonBackend has no pre-loaded results."""
		ctx = ActionContext(
			targets=['t.com'],
			model='m',
			context={'workspace_id': 'ws1'},
		)
		engine = ctx.get_query_engine()

		self.assertIsNone(engine.backend._results)

	# -- scope=workspace + mongodb --

	def test_workspace_scope_mongodb_backend(self):
		"""scope=workspace with mongodb driver selects MongoDBBackend."""
		from secator.query.mongodb import MongoDBBackend

		ctx = ActionContext(
			targets=['t.com'],
			model='m',
			context={'workspace_id': 'ws1', 'drivers': ['mongodb']},
		)
		engine = ctx.get_query_engine()

		self.assertIsInstance(engine.backend, MongoDBBackend)

	def test_workspace_scope_mongodb_search(self):
		"""scope=workspace mongodb search calls db.findings.find."""
		mock_cursor = MagicMock()
		mock_cursor.__iter__ = MagicMock(
			return_value=iter(
				[
					{'_id': 'abc', '_type': 'vulnerability', 'name': 'SQLi'},
				]
			)
		)
		mock_cursor.limit.return_value = mock_cursor

		mock_db = MagicMock()
		mock_db.findings.find.return_value = mock_cursor
		mock_client = MagicMock()
		mock_client.main = mock_db

		ctx = ActionContext(
			targets=['t.com'],
			model='m',
			context={'workspace_id': 'ws1', 'drivers': ['mongodb']},
		)
		engine = ctx.get_query_engine()
		engine.backend._client = mock_client
		found = engine.search({'_type': 'vulnerability'}, limit=10)

		self.assertEqual(len(found), 1)
		self.assertEqual(found[0]['name'], 'SQLi')
		# Verify base query was merged (workspace_id, _tagged)
		call_args = mock_db.findings.find.call_args[0][0]
		self.assertEqual(call_args['_context.workspace_id'], 'ws1')
		# self.assertTrue(call_args["_tagged"])

	def test_workspace_scope_mongodb_count(self):
		"""scope=workspace mongodb count calls db.findings.count_documents."""
		mock_db = MagicMock()
		mock_db.findings.count_documents.return_value = 5
		mock_client = MagicMock()
		mock_client.main = mock_db

		ctx = ActionContext(
			targets=['t.com'],
			model='m',
			context={'workspace_id': 'ws1', 'drivers': ['mongodb']},
		)
		engine = ctx.get_query_engine()
		engine.backend._client = mock_client
		count = engine.count({'_type': 'vulnerability'})

		self.assertEqual(count, 5)
		call_args = mock_db.findings.count_documents.call_args[0][0]
		self.assertEqual(call_args['_context.workspace_id'], 'ws1')

	# -- scope=workspace + api --

	def test_workspace_scope_api_backend(self):
		"""scope=workspace with api driver selects ApiBackend."""
		from secator.query.api import ApiBackend

		ctx = ActionContext(
			targets=['t.com'],
			model='m',
			context={'workspace_id': 'ws1', 'drivers': ['api']},
		)
		engine = ctx.get_query_engine()

		self.assertIsInstance(engine.backend, ApiBackend)

	@patch('secator.query.api.requests.request')
	def test_workspace_scope_api_search(self, mock_request):
		"""scope=workspace api search calls POST to search endpoint."""
		mock_response = MagicMock()
		mock_response.json.return_value = [
			{'_type': 'vulnerability', 'name': 'SQLi'},
		]
		mock_response.raise_for_status = MagicMock()
		mock_request.return_value = mock_response

		ctx = ActionContext(
			targets=['t.com'],
			model='m',
			context={'workspace_id': 'ws1', 'drivers': ['api']},
		)
		engine = ctx.get_query_engine()
		found = engine.search({'_type': 'vulnerability'}, limit=10)

		self.assertEqual(len(found), 1)
		mock_request.assert_called_once()
		# Verify POST was used
		call_kwargs = mock_request.call_args
		self.assertEqual(call_kwargs[1]['method'], 'POST')

	@patch('secator.query.api.requests.request')
	def test_workspace_scope_api_count(self, mock_request):
		"""scope=workspace api count returns total from response."""
		mock_response = MagicMock()
		mock_response.json.return_value = {'total': 42}
		mock_response.raise_for_status = MagicMock()
		mock_request.return_value = mock_response

		ctx = ActionContext(
			targets=['t.com'],
			model='m',
			context={'workspace_id': 'ws1', 'drivers': ['api']},
		)
		engine = ctx.get_query_engine()
		count = engine.count({'_type': 'vulnerability'})

		self.assertEqual(count, 42)


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestHandleAddFinding(unittest.TestCase):
	"""Tests for the _handle_add_finding action handler."""

	def test_add_vulnerability(self):
		ctx = ActionContext(targets=['t.com'], model='m')
		results = list(
			_handle_add_finding(
				{
					'action': 'add_finding',
					'_type': 'vulnerability',
					'name': 'SQL Injection',
					'severity': 'critical',
					'matched_at': 'http://t.com/login',
				},
				ctx,
			)
		)

		self.assertEqual(len(results), 2)
		self.assertIsInstance(results[1], Vulnerability)
		self.assertEqual(results[1].name, 'SQL Injection')
		self.assertEqual(results[1].severity, 'critical')
		self.assertEqual(results[1].matched_at, 'http://t.com/login')

	def test_add_url(self):
		ctx = ActionContext(targets=['t.com'], model='m')
		results = list(
			_handle_add_finding(
				{
					'action': 'add_finding',
					'_type': 'url',
					'url': 'http://t.com/admin',
					'status_code': 200,
				},
				ctx,
			)
		)

		self.assertEqual(len(results), 2)
		self.assertIsInstance(results[1], Url)
		self.assertEqual(results[1].url, 'http://t.com/admin')
		self.assertEqual(results[1].status_code, 200)

	def test_add_finding_unknown_type(self):
		ctx = ActionContext(targets=['t.com'], model='m')
		results = list(
			_handle_add_finding(
				{
					'action': 'add_finding',
					'_type': 'nonexistent',
				},
				ctx,
			)
		)

		self.assertEqual(len(results), 1)
		self.assertIsInstance(results[0], Warning)
		self.assertIn('nonexistent', results[0].message)

	def test_add_finding_invalid_fields(self):
		ctx = ActionContext(targets=['t.com'], model='m')
		results = list(
			_handle_add_finding(
				{
					'action': 'add_finding',
					'_type': 'vulnerability',
					'bad_field': 'value',
				},
				ctx,
			)
		)

		self.assertEqual(len(results), 1)
		self.assertIsInstance(results[0], Error)

	def test_add_finding_decrypts_values(self):
		encryptor = MagicMock()
		encryptor.decrypt.side_effect = lambda x: x.replace('ENC_', '')
		ctx = ActionContext(targets=['t.com'], model='m', encryptor=encryptor)
		results = list(
			_handle_add_finding(
				{
					'action': 'add_finding',
					'_type': 'vulnerability',
					'name': 'XSS',
					'matched_at': 'ENC_http://t.com/search',
				},
				ctx,
			)
		)

		self.assertEqual(len(results), 2)
		self.assertIsInstance(results[1], Vulnerability)
		self.assertEqual(results[1].matched_at, 'http://t.com/search')

	def test_coerce_finding_fields_scalar_types(self):
		# LLMs send wrong-typed scalars (bool as "true", float/int as strings).
		# The coercion helper fixes them to the declared field types.
		data = _coerce_finding_fields(
			Vulnerability,
			{
				'name': 'SQL Injection',
				'verified': 'true',
				'cvss_score': '7.5',
				'severity_nb': '3',
			},
		)
		self.assertIs(data['verified'], True)
		self.assertIsInstance(data['verified'], bool)
		self.assertEqual(data['cvss_score'], 7.5)
		self.assertIsInstance(data['cvss_score'], float)
		self.assertEqual(data['severity_nb'], 3)
		self.assertIsInstance(data['severity_nb'], int)
		# str fields are left untouched.
		self.assertEqual(data['name'], 'SQL Injection')
		# Coerced data validates clean.
		self.assertEqual(Vulnerability.validate_fields(data), [])

	def test_add_finding_coerces_scalar_types(self):
		# End-to-end: wrong-typed scalars flow through the handler and validate
		# clean, producing a Vulnerability with the coerced bool/float values.
		ctx = ActionContext(targets=['t.com'], model='m')
		results = list(
			_handle_add_finding(
				{
					'action': 'add_finding',
					'_type': 'vulnerability',
					'name': 'SQL Injection',
					'matched_at': 'http://t.com/login',
					'verified': 'true',
					'cvss_score': '7.5',
					'severity_nb': '3',
				},
				ctx,
			)
		)

		# No validation Error: the sloppy types were coerced before validation.
		self.assertEqual(len(results), 2)
		vuln = results[1]
		self.assertIsInstance(vuln, Vulnerability)
		self.assertIs(vuln.verified, True)
		self.assertIsInstance(vuln.verified, bool)
		self.assertEqual(vuln.cvss_score, 7.5)
		self.assertIsInstance(vuln.cvss_score, float)

	def test_add_finding_unparseable_bool_surfaces_error(self):
		# An unparseable value must NOT be silently dropped; validation reports it.
		ctx = ActionContext(targets=['t.com'], model='m')
		results = list(
			_handle_add_finding(
				{
					'action': 'add_finding',
					'_type': 'vulnerability',
					'name': 'SQL Injection',
					'matched_at': 'http://t.com/login',
					'verified': 'maybe',
				},
				ctx,
			)
		)

		self.assertEqual(len(results), 1)
		self.assertIsInstance(results[0], Error)
		self.assertIn('verified', results[0].message)


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestRunBatch(unittest.TestCase):
    """Tests for _run_batch parallel execution."""

    def test_run_batch_executes_all_actions(self):
        from secator.ai.actions import _run_batch, ActionContext

        ctx = ActionContext(targets=["t.com"], model="m", dry_run=True, max_workers=3)
        actions = [
            {"action": "shell", "command": "echo a"},
            {"action": "shell", "command": "echo b"},
            {"action": "shell", "command": "echo c"},
        ]

        results = list(_run_batch(actions, ctx))

        # Should have Info + 3x (Info dry run)
        info_results = [r for r in results if isinstance(r, Info)]
        self.assertGreaterEqual(len(info_results), 3)

    def test_run_batch_uses_rich_progress(self):
        from secator.ai.actions import _run_batch, ActionContext

        ctx = ActionContext(targets=["t.com"], model="m", dry_run=True, max_workers=2)
        actions = [
            {"action": "shell", "command": "echo a"},
            {"action": "shell", "command": "echo b"},
        ]

        results = list(_run_batch(actions, ctx))

        # Should have dry run Info results (no batch Info since Rich progress handles display)
        info_results = [r for r in results if isinstance(r, Info)]
        self.assertGreaterEqual(len(info_results), 2)

    def test_run_batch_empty_actions(self):
        from secator.ai.actions import _run_batch, ActionContext

        ctx = ActionContext(targets=["t.com"], model="m")
        results = list(_run_batch([], ctx))

        self.assertEqual(len(results), 1)
        self.assertIsInstance(results[0], Warning)


if __name__ == '__main__':
	unittest.main()
