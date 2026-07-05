# tests/unit/test_ai_actions.py
"""Tests for AI action handlers - shell execution, queries, decryption."""

import unittest
from unittest.mock import patch, MagicMock

from secator.definitions import ADDONS_ENABLED

if ADDONS_ENABLED['ai']:
	from secator.ai.actions import (
		ActionContext, dispatch_action, _handle_follow_up, _handle_shell,
		_handle_query, _handle_add_finding, _run_runner, _decrypt_dict,
		_build_hooks_from_context, _coerce_finding_fields, _sanitize_child_opts,
		_build_child_hooks_or_denial,
		_MAX_CHILD_ITERATIONS, _MAX_SUBAGENT_DEPTH, _MAX_SUBAGENTS_PER_TURN,
		_MAX_SHELL_OUTPUT_CHARS, _truncate,
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

	def test_decrypt_non_dict_returned_unchanged(self):
		"""Backstop: a non-dict (e.g. a stringified query arg) must not raise
		`.items()` — it is returned unchanged instead of crashing the action."""
		encryptor = MagicMock()
		self.assertEqual(_decrypt_dict('{"_type": "url"}', encryptor), '{"_type": "url"}')
		self.assertEqual(_decrypt_dict(['a', 'b'], encryptor), ['a', 'b'])
		encryptor.decrypt.assert_not_called()

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

	@patch('secator.ai.actions.subprocess.run')
	def test_shell_output_capped_when_over_limit(self, mock_run):
		# M1: huge stdout must be truncated to <= cap + marker and carry the marker.
		big = "HEAD_LINE\n" + ("x" * (_MAX_SHELL_OUTPUT_CHARS * 3)) + "\nTAIL_LINE"
		mock_run.return_value = MagicMock(stdout=big, stderr='')
		ctx = ActionContext(targets=['t.com'], model='m')

		results = list(_handle_shell({'action': 'shell', 'command': 'dump'}, ctx))

		content = results[1].content
		self.assertLess(len(content), len(big))
		# body is bounded by the cap (plus the short marker line)
		self.assertLessEqual(len(content), _MAX_SHELL_OUTPUT_CHARS + 40)
		self.assertIn('truncated', content)
		# head + tail preserved so the model sees the start AND the final lines
		self.assertIn('HEAD_LINE', content)
		self.assertIn('TAIL_LINE', content)

	@patch('secator.ai.actions.subprocess.run')
	def test_shell_output_short_passes_through_unchanged(self, mock_run):
		# M1: short output must pass through untouched (no marker).
		mock_run.return_value = MagicMock(stdout='root\n', stderr='')
		ctx = ActionContext(targets=['t.com'], model='m')

		results = list(_handle_shell({'action': 'shell', 'command': 'whoami'}, ctx))

		self.assertEqual(results[1].content, 'root\n')
		self.assertNotIn('truncated', results[1].content)

	def test_truncate_short_text_unchanged(self):
		self.assertEqual(_truncate('short', 100), 'short')

	def test_truncate_keeps_head_and_tail(self):
		text = 'START' + ('m' * 500) + 'END'
		out = _truncate(text, 100)
		self.assertLessEqual(len(out), 100 + 40)
		self.assertTrue(out.startswith('START'))
		self.assertTrue(out.endswith('END'))
		self.assertIn('truncated', out)

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
		"""A NON-local backend (mongodb/api) without a workspace_id yields the
		'No workspace' guard. The local driver is exempt (it answers from in-memory
		results — see test_query_local_driver_exempt_from_workspace_guard)."""
		mock_engine = MagicMock()
		mock_engine.backend.name = "mongodb"
		ctx = ActionContext(targets=['t.com'], model='m', context={})
		with patch.object(ctx, 'get_query_engine', return_value=mock_engine):
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
	def test_query_stringified_json_is_coerced(self, mock_get_engine):
		"""A model that passes `query` as a JSON *string* (schema says object) must
		still work — coerced to a dict, then searched. Regression for the
		AttributeError('str' object has no attribute 'items') in _decrypt_dict."""
		mock_engine = MagicMock()
		mock_engine.search.return_value = [{'_type': 'url', '_context': {}}]
		mock_get_engine.return_value = mock_engine
		# Encryptor active is the exact condition that made the original crash fire.
		encryptor = MagicMock()
		encryptor.decrypt.side_effect = lambda s: s
		ctx = ActionContext(targets=['t.com'], model='m', context={'workspace_id': 'ws1'}, encryptor=encryptor)

		results = list(_handle_query(
			{'action': 'query', 'query': '{"_type": "url", "verified": true}'}, ctx))

		self.assertFalse([r for r in results if isinstance(r, Error)], 'stringified query must not error')
		mock_engine.search.assert_called_once_with({'_type': 'url', 'verified': True}, limit=100)

	def test_query_unparseable_string_returns_clean_error(self):
		"""A non-JSON string yields an Error the LLM can act on — not a crash."""
		ctx = ActionContext(targets=['t.com'], model='m', context={'workspace_id': 'ws1'})
		results = list(_handle_query({'action': 'query', 'query': 'not json at all'}, ctx))
		errors = [r for r in results if isinstance(r, Error)]
		self.assertEqual(len(errors), 1)
		self.assertIn('JSON object', errors[0].message)

	def test_query_non_dict_returns_clean_error(self):
		"""A non-dict, non-str query (e.g. a list) yields a clean Error, not a crash."""
		ctx = ActionContext(targets=['t.com'], model='m', context={'workspace_id': 'ws1'})
		results = list(_handle_query({'action': 'query', 'query': ['_type', 'url']}, ctx))
		errors = [r for r in results if isinstance(r, Error)]
		self.assertEqual(len(errors), 1)
		self.assertIn('JSON object', errors[0].message)

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

	def test_union_live_results_dedup_and_filter(self):
		"""_union_live_results filters live by the query, merges into backend results,
		and dedupes by _uuid (backend wins)."""
		from secator.ai.actions import _union_live_results
		persisted = [{"_uuid": "a", "_type": "port"}]
		live = [{"_uuid": "a", "_type": "port"},   # dup -> deduped
				{"_uuid": "b", "_type": "port"},   # new -> included
				{"_uuid": "c", "_type": "url"}]    # wrong type -> filtered out by the query
		out = _union_live_results(list(persisted), live, {"_type": "port"}, 100)
		self.assertEqual(sorted(r["_uuid"] for r in out), ["a", "b"])
		# no live results -> persisted returned unchanged
		self.assertEqual(_union_live_results([{"_uuid": "z"}], [], {}, 0), [{"_uuid": "z"}])

	def test_query_local_driver_unions_live_results(self):
		"""Local (json) driver: query_workspace unions this run's in-memory findings
		with the backend (JSON exporter only writes to disk at end-of-run)."""
		mock_engine = MagicMock()
		mock_engine.backend.name = "json"
		mock_engine.search.return_value = [{"_uuid": "disk1", "_type": "port", "_context": {}}]
		ctx = ActionContext(targets=['t'], model='m', context={'workspace_id': 'ws1'},
							 results=[{"_uuid": "live1", "_type": "port", "_context": {}}])
		with patch.object(ctx, 'get_query_engine', return_value=mock_engine):
			results = list(_handle_query({'action': 'query', 'query': {'_type': 'port'}}, ctx))
		uuids = {r.get('_uuid') for r in results if isinstance(r, dict)}
		self.assertIn('disk1', uuids)   # backend result
		self.assertIn('live1', uuids)   # unioned live in-memory result

	def test_query_mongodb_driver_does_not_union(self):
		"""Non-local backend (mongodb) is queried normally — live self.results are NOT unioned."""
		mock_engine = MagicMock()
		mock_engine.backend.name = "mongodb"
		mock_engine.search.return_value = [{"_uuid": "db1", "_type": "port", "_context": {}}]
		ctx = ActionContext(targets=['t'], model='m', context={'workspace_id': 'ws1'},
							 results=[{"_uuid": "live1", "_type": "port", "_context": {}}])
		with patch.object(ctx, 'get_query_engine', return_value=mock_engine):
			results = list(_handle_query({'action': 'query', 'query': {'_type': 'port'}}, ctx))
		uuids = {r.get('_uuid') for r in results if isinstance(r, dict)}
		self.assertIn('db1', uuids)
		self.assertNotIn('live1', uuids)   # not unioned for non-local backends

	def test_query_local_driver_exempt_from_workspace_guard(self):
		"""Local driver with NO workspace_id is not blocked by the 'No workspace' guard —
		it answers from in-memory results."""
		mock_engine = MagicMock()
		mock_engine.backend.name = "json"
		mock_engine.search.return_value = []
		ctx = ActionContext(targets=['t'], model='m', context={},   # no workspace_id
							 results=[{"_uuid": "live1", "_type": "port", "_context": {}}])
		with patch.object(ctx, 'get_query_engine', return_value=mock_engine):
			results = list(_handle_query({'action': 'query', 'query': {'_type': 'port'}}, ctx))
		warnings = [r for r in results if isinstance(r, Warning)]
		self.assertFalse(any('No workspace' in getattr(w, 'message', '') for w in warnings))
		uuids = {r.get('_uuid') for r in results if isinstance(r, dict)}
		self.assertIn('live1', uuids)


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
		# non-empty: context has drivers, so empty hooks would trip the M2 guard
		mock_build_hooks.return_value = {'fake': ['hook']}
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
class TestSanitizeChildOpts(unittest.TestCase):
	"""Tests for _sanitize_child_opts (C1: LLM-supplied subagent opts allow-list)."""

	def test_strips_dangerous_and_control_keys(self):
		opts = {
			'dangerous': True, 'interactive': 'local', 'hooks': {'x': 1},
			'sync': False, 'subagent': True, 'tty': True, 'dry_run': True,
			'exporters': ['csv'], 'enable_reports': False,
		}
		clean = _sanitize_child_opts(opts)
		self.assertEqual(clean, {})

	def test_strips_print_star_keys(self):
		clean = _sanitize_child_opts({'print_cmd': True, 'print_item': False, 'print_anything': 1})
		self.assertEqual(clean, {})

	def test_keeps_benign_task_opts(self):
		clean = _sanitize_child_opts({'ports': '80,443', 'rate_limit': 100, 'mode': 'attack'})
		self.assertEqual(clean, {'ports': '80,443', 'rate_limit': 100, 'mode': 'attack'})

	def test_clamps_max_iterations(self):
		clean = _sanitize_child_opts({'max_iterations': 9999})
		self.assertEqual(clean['max_iterations'], _MAX_CHILD_ITERATIONS)
		clean = _sanitize_child_opts({'max_iterations': 5})
		self.assertEqual(clean['max_iterations'], 5)
		# bool / non-numeric max_iterations is dropped (bool is an int subclass)
		self.assertNotIn('max_iterations', _sanitize_child_opts({'max_iterations': True}))
		self.assertNotIn('max_iterations', _sanitize_child_opts({'max_iterations': 'lots'}))

	def test_non_dict_returns_empty(self):
		self.assertEqual(_sanitize_child_opts(None), {})
		self.assertEqual(_sanitize_child_opts('dangerous'), {})

	@patch('secator.ai.actions.TemplateLoader')
	@patch('secator.ai.actions.Task')
	@patch('secator.ai.actions._build_hooks_from_context')
	def test_run_runner_neutralizes_dangerous_and_interactive(self, mock_build_hooks, mock_task_cls, _mock_tpl):
		"""C1: an LLM emitting opts={'dangerous': True, 'interactive': 'local'} must NOT
		propagate either into the spawned child's run_opts — dangerous is forced False
		and interactive (a control key) is stripped."""
		mock_build_hooks.return_value = {}
		mock_runner = MagicMock()
		mock_runner.id = 'runner123'
		mock_runner.reports_folder = None
		mock_runner.__iter__.return_value = iter([])
		mock_task_cls.return_value = mock_runner

		ctx = ActionContext(targets=['t.com'], model='m', context={'workspace_id': 'ws1'})
		action = {
			'action': 'task', 'name': 'nmap', 'targets': ['10.0.0.1'],
			'opts': {'dangerous': True, 'interactive': 'local', 'ports': '80'},
		}

		list(_run_runner(action, ctx, 'task'))

		_, kwargs = mock_task_cls.call_args
		run_opts = kwargs.get('run_opts', {})
		self.assertEqual(run_opts.get('dangerous'), False)
		self.assertNotEqual(run_opts.get('interactive'), 'local')
		# benign task opt still passes through
		self.assertEqual(run_opts.get('ports'), '80')

	@patch('secator.ai.actions.TemplateLoader')
	@patch('secator.ai.actions.Task')
	@patch('secator.ai.actions._build_hooks_from_context')
	def test_run_runner_ai_subagent_forced_flags_over_llm_opts(self, mock_build_hooks, mock_task_cls, _mock_tpl):
		"""Spawning an `ai` subagent with hostile opts: subagent forced True,
		interactive forced False, dangerous forced False regardless of LLM input."""
		mock_build_hooks.return_value = {}
		mock_runner = MagicMock()
		mock_runner.id = 'runner123'
		mock_runner.reports_folder = None
		mock_runner.__iter__.return_value = iter([])
		mock_task_cls.return_value = mock_runner

		ctx = ActionContext(targets=['t.com'], model='m', context={'workspace_id': 'ws1'})
		action = {
			'action': 'task', 'name': 'ai', 'targets': ['10.0.0.1'],
			'opts': {'dangerous': True, 'interactive': 'local', 'subagent': False},
		}

		list(_run_runner(action, ctx, 'task'))

		_, kwargs = mock_task_cls.call_args
		run_opts = kwargs.get('run_opts', {})
		self.assertEqual(run_opts.get('dangerous'), False)
		self.assertEqual(run_opts.get('interactive'), False)
		self.assertEqual(run_opts.get('subagent'), True)


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
class TestChildHooksOrDenial(unittest.TestCase):
	"""M2: refuse to spawn a persistence-less child when the parent has drivers."""

	@patch('secator.ai.actions._build_hooks_from_context')
	def test_parent_no_drivers_empty_hooks_allowed(self, mock_build):
		# pure local/no-persistence run: empty hooks child is expected, no denial
		mock_build.return_value = {}
		hooks, denial = _build_child_hooks_or_denial({'workspace_id': 'ws1'})
		self.assertEqual(hooks, {})
		self.assertIsNone(denial)

	@patch('secator.ai.actions._build_hooks_from_context')
	def test_parent_drivers_present_hooks_pass_through(self, mock_build):
		# normal spawn: drivers present + non-empty hooks -> pass through unchanged
		sentinel = {'fake': ['hook']}
		mock_build.return_value = sentinel
		hooks, denial = _build_child_hooks_or_denial({'drivers': ['mongodb']})
		self.assertEqual(hooks, sentinel)
		self.assertIsNone(denial)

	@patch('secator.ai.actions._build_hooks_from_context')
	def test_parent_drivers_but_empty_hooks_denied(self, mock_build):
		# parent HAS drivers but rebuild produced no hooks -> refuse, surface Warning
		mock_build.return_value = {}
		hooks, denial = _build_child_hooks_or_denial({'drivers': ['mongodb']})
		self.assertEqual(hooks, {})
		self.assertIsInstance(denial, Warning)
		self.assertIn('drop findings', denial.message)

	@patch('secator.ai.actions._build_hooks_from_context')
	def test_rebuild_raise_with_drivers_denied_not_swallowed(self, mock_build):
		# a raising rebuild must not degrade to hooks={} silently -> Warning
		mock_build.side_effect = RuntimeError('boom')
		hooks, denial = _build_child_hooks_or_denial({'drivers': ['mongodb']})
		self.assertEqual(hooks, {})
		self.assertIsInstance(denial, Warning)
		self.assertIn('rebuild failed', denial.message)

	@patch('secator.ai.actions._build_hooks_from_context')
	def test_rebuild_raise_no_drivers_allowed(self, mock_build):
		# no parent drivers: a rebuild error still yields an allowed empty-hooks child
		mock_build.side_effect = RuntimeError('boom')
		hooks, denial = _build_child_hooks_or_denial({'workspace_id': 'ws1'})
		self.assertEqual(hooks, {})
		self.assertIsNone(denial)

	@patch('secator.ai.actions.TemplateLoader')
	@patch('secator.ai.actions.Task')
	@patch('secator.ai.actions._build_hooks_from_context')
	def test_run_runner_refuses_spawn_on_lost_persistence(self, mock_build, mock_task_cls, _tpl):
		# end-to-end: parent has drivers, rebuild empty -> _run_runner yields a
		# Warning and never constructs the child runner
		mock_build.return_value = {}
		ctx = ActionContext(
			targets=['t.com'], model='m',
			context={'workspace_id': 'ws1', 'drivers': ['mongodb']},
		)
		action = {'action': 'task', 'name': 'nmap', 'targets': ['10.0.0.1']}
		results = list(_run_runner(action, ctx, 'task'))
		mock_task_cls.assert_not_called()
		warnings = [r for r in results if isinstance(r, Warning)]
		self.assertEqual(len(warnings), 1)
		self.assertIn('denied', warnings[0].message)

	@patch('secator.ai.actions.TemplateLoader')
	@patch('secator.ai.actions.Task')
	@patch('secator.ai.actions._build_hooks_from_context')
	def test_run_runner_no_drivers_spawns_normally(self, mock_build, mock_task_cls, _tpl):
		# parent has NO drivers: empty-hooks child still spawns (no false alarm)
		mock_build.return_value = {}
		mock_runner = MagicMock()
		mock_runner.id = 'runner123'
		mock_runner.reports_folder = None
		mock_runner.__iter__.return_value = iter([])
		mock_task_cls.return_value = mock_runner
		ctx = ActionContext(targets=['t.com'], model='m', context={'workspace_id': 'ws1'})
		action = {'action': 'task', 'name': 'nmap', 'targets': ['10.0.0.1']}
		results = list(_run_runner(action, ctx, 'task'))
		mock_task_cls.assert_called_once()
		self.assertFalse([r for r in results if isinstance(r, Warning)])


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

    def test_get_action_label_tolerates_stringified_opts(self):
        """Regression: a str `opts` (model stringified it) must not crash the
        batch label with AttributeError('str' object has no attribute 'get')."""
        from secator.ai.actions import _get_action_label
        label = _get_action_label(
            {"action": "task", "name": "nmap", "targets": ["10.0.0.1"], "opts": '{"session_name": "x"}'})
        self.assertEqual(label, "nmap on 10.0.0.1")  # falls back to name-on-target, no crash


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestCheckGuardrailsFailClosed(unittest.TestCase):
	"""H10: prompts exhausted with the decision still 'ask' must fail CLOSED (deny)."""

	def test_unresolved_after_max_rounds_denies(self):
		from secator.ai.actions import check_guardrails_sync
		# permission engine that never resolves: always 'ask', no shell/target/path layer
		res = MagicMock(decision="ask", shell_command="", targets=[], paths=[], reason="needs approval")
		engine = MagicMock()
		engine.check_action.return_value = res
		ctx = ActionContext(targets=['t.com'], model='m')
		ctx.permission_engine = engine
		denial, _items = check_guardrails_sync({"action": "shell", "command": "x"}, ctx)
		self.assertIsNotNone(denial, "exhausted-but-unresolved guardrail must deny, not return None")
		self.assertIn("unresolved", denial)


class TestApprovalAllowList(unittest.TestCase):
	"""Ask-loop approval must be an explicit allow-list: only "allow" proceeds."""

	def _run(self, answer):
		from secator.ai.actions import check_guardrails_sync
		ask = MagicMock(decision="ask", shell_command="somecmd", targets=[], paths=[], reason="needs approval")
		allow = MagicMock(decision="allow", shell_command="", targets=[], paths=[], reason="")
		engine = MagicMock()
		engine.check_action.side_effect = [ask, allow]
		backend = MagicMock()
		backend.ask_user.return_value = None if answer is None else {"answer": answer}
		ctx = ActionContext(targets=['t.com'], model='m')
		ctx.permission_engine = engine
		ctx.backend = backend
		denial, _items = check_guardrails_sync({"action": "shell", "command": "somecmd"}, ctx)
		return denial

	def test_allow_proceeds(self):
		self.assertIsNone(self._run("allow"))

	def test_deny_denies(self):
		self.assertIsNotNone(self._run("deny"))

	def test_unexpected_answer_denies(self):
		# an out-of-vocabulary token must NOT be treated as approval (fail closed)
		self.assertIsNotNone(self._run("sure"))
		self.assertIsNotNone(self._run("allow_all_typo"))

	def test_none_response_denies(self):
		self.assertIsNotNone(self._run(None))


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestSubagentFanoutCap(unittest.TestCase):
	"""H4: recursion depth + per-turn fan-out caps on AI-subagent spawns."""

	def _mock_task(self, mock_task_cls):
		runner = MagicMock()
		runner.id = 'runner123'
		runner.reports_folder = None
		runner.__iter__.return_value = iter([])
		mock_task_cls.return_value = runner
		return runner

	def test_depth_cap_refuses_spawn(self):
		"""Spawning an AI subagent at/over _MAX_SUBAGENT_DEPTH is denied."""
		ctx = ActionContext(
			targets=['t.com'], model='m',
			context={'ai_subagent_depth': _MAX_SUBAGENT_DEPTH},
		)
		action = {'action': 'task', 'name': 'ai', 'targets': ['t.com']}

		with patch('secator.ai.actions.Task') as mock_task_cls:
			results = list(_run_runner(action, ctx, 'task'))

		mock_task_cls.assert_not_called()  # denied before constructing the child
		self.assertEqual(len(results), 1)
		self.assertIsInstance(results[0], Warning)
		self.assertIn('depth cap', results[0].message)
		# no Ai task item emitted (spawn refused)
		self.assertFalse([r for r in results if isinstance(r, Ai) and r.ai_type == 'task'])

	def test_per_turn_breadth_cap_refuses_spawn(self):
		"""In a batch, spawning past _MAX_SUBAGENTS_PER_TURN is denied."""
		ctx = ActionContext(
			targets=['t.com'], model='m', in_batch=True,
			context={'ai_subagent_turn_count': _MAX_SUBAGENTS_PER_TURN},
		)
		action = {'action': 'task', 'name': 'ai', 'targets': ['t.com']}

		with patch('secator.ai.actions.Task') as mock_task_cls:
			results = list(_run_runner(action, ctx, 'task'))

		mock_task_cls.assert_not_called()
		self.assertEqual(len(results), 1)
		self.assertIsInstance(results[0], Warning)
		self.assertIn('fan-out cap', results[0].message)

	@patch('secator.ai.actions.TemplateLoader')
	@patch('secator.ai.actions.Task')
	@patch('secator.ai.actions._build_hooks_from_context')
	def test_normal_depth1_spawn_succeeds(self, mock_build_hooks, mock_task_cls, _mock_tpl):
		"""A first-level AI subagent (depth 0 -> 1) still spawns; child inherits depth+1."""
		mock_build_hooks.return_value = {}
		self._mock_task(mock_task_cls)

		ctx = ActionContext(targets=['t.com'], model='m', context={})  # depth 0, not in a batch
		action = {'action': 'task', 'name': 'ai', 'targets': ['t.com']}

		results = list(_run_runner(action, ctx, 'task'))

		mock_task_cls.assert_called_once()
		ai_items = [r for r in results if isinstance(r, Ai) and r.ai_type == 'task']
		self.assertEqual(len(ai_items), 1)
		self.assertFalse([r for r in results if isinstance(r, Warning)])
		# child context carries incremented depth
		_, kwargs = mock_task_cls.call_args
		self.assertEqual(kwargs.get('context', {}).get('ai_subagent_depth'), 1)


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestChildContextParenting(unittest.TestCase):
	"""A spawned sub-runner must get a CLEAN identity: it inherits the conversation
	session_id + drivers but NOT the parent's runner-doc id, so it mints its own doc
	(linked to the conversation by session_id), instead of clobbering the parent."""

	def test_child_context_strips_parent_identity_keeps_session(self):
		from secator.ai.actions import _get_result_context, ActionContext
		ctx = ActionContext(
			targets=['t.com'], model='m',
			context={
				'workspace_id': 'ws1', 'workspace_name': 'w', 'drivers': ['mongodb'],
				'task_id': 'PARENT_AI_ID',          # the parent ai task's own doc id
				'session_id': 'conv-1',
			},
			session_id='conv-1',
		)
		action = {'action': 'task', 'name': 'nmap', 'tool_call_id': 'tc1', 'tool_call_name': 'run_task'}
		child = _get_result_context(action, ctx)
		# keeps the conversation link + drivers/workspace
		self.assertEqual(child['session_id'], 'conv-1')
		self.assertEqual(child['drivers'], ['mongodb'])
		self.assertEqual(child['workspace_id'], 'ws1')
		# marks it a child
		self.assertTrue(child.get('has_parent'))
		# does NOT inherit the parent's runner-doc identity (would clobber / suppress its own doc)
		self.assertNotIn('task_id', child)
		self.assertNotIn('workflow_id', child)
		self.assertNotIn('scan_id', child)


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestBuildSubagentPrompt(unittest.TestCase):
	def test_structure_sections_and_objective(self):
		from secator.ai.actions import build_subagent_prompt
		p = build_subagent_prompt("Test auth on the API", ["10.0.0.1", "app.x.com"], "- Port 443 open")
		self.assertIn("## Objective", p)
		self.assertIn("Test auth on the API", p)          # objective verbatim
		self.assertIn("## Scope", p)
		self.assertIn("10.0.0.1", p)
		self.assertIn("app.x.com", p)
		self.assertIn("## Already known", p)
		self.assertIn("- Port 443 open", p)               # evidence injected
		self.assertIn("## Expected output", p)

	def test_empty_evidence_renders_none(self):
		from secator.ai.actions import build_subagent_prompt
		p = build_subagent_prompt("Do X", ["t.com"], "")
		self.assertIn("(none", p.lower())                 # explicit "none" marker


@unittest.skipUnless(ADDONS_ENABLED['ai'], 'ai addon not installed')
class TestGatherSubagentEvidence(unittest.TestCase):
	def test_queries_targets_and_formats(self):
		from secator.ai.actions import _gather_subagent_evidence, ActionContext
		mock_engine = MagicMock()
		mock_engine.search.return_value = [
			{"_type": "port", "ip": "10.0.0.1", "port": 443},
			{"_type": "url", "url": "http://app.x.com/login"},
		]
		ctx = ActionContext(targets=[], model='m', context={'workspace_id': 'ws1'})
		with patch.object(ctx, 'get_query_engine', return_value=mock_engine):
			out = _gather_subagent_evidence(ctx, ["10.0.0.1", "app.x.com"], limit=40)
		# queried by an $or over the targets
		q = mock_engine.search.call_args[0][0]
		self.assertIn("$or", q)
		# formatted a compact summary
		self.assertIn("port", out)
		self.assertIn("10.0.0.1", out)
		self.assertIn("url", out)

	def test_no_targets_returns_empty(self):
		from secator.ai.actions import _gather_subagent_evidence, ActionContext
		ctx = ActionContext(targets=[], model='m', context={})
		self.assertEqual(_gather_subagent_evidence(ctx, [], limit=40), "")

	def test_search_error_returns_empty(self):
		from secator.ai.actions import _gather_subagent_evidence, ActionContext
		mock_engine = MagicMock()
		mock_engine.search.side_effect = Exception("boom")
		ctx = ActionContext(targets=[], model='m', context={'workspace_id': 'ws1'})
		with patch.object(ctx, 'get_query_engine', return_value=mock_engine):
			self.assertEqual(_gather_subagent_evidence(ctx, ["t"], limit=40), "")


if __name__ == '__main__':
	unittest.main()
