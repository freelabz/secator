"""The api query backend surfaces a missing / rejected API key as an error, not an empty result."""
import unittest
from unittest import mock

from click.testing import CliRunner

from secator.query._base import QueryBackendError
from secator.query.api import ApiBackend


def _response(status_code, payload=None):
	resp = mock.Mock()
	resp.status_code = status_code
	resp.ok = status_code < 400
	resp.json.return_value = payload if payload is not None else {}

	def raise_for_status():
		if status_code >= 400:
			import requests
			raise requests.HTTPError(f'{status_code} Error')
	resp.raise_for_status.side_effect = raise_for_status
	return resp


class TestQueryBackendErrors(unittest.TestCase):

	def _backend(self, key):
		backend = ApiBackend(workspace_id='ws1')
		backend.api_key = key
		return backend

	def test_missing_key_401_explains_how_to_configure_one(self):
		with mock.patch('secator.query.api._session.request', return_value=_response(401)):
			with self.assertRaises(QueryBackendError) as cm:
				self._backend('')._make_request('GET', 'workspaces')
		self.assertIn('no API key is configured', cm.exception.message)
		self.assertIn('addons.api.key', cm.exception.message)

	def test_rejected_key_403_says_the_key_is_invalid(self):
		with mock.patch('secator.query.api._session.request', return_value=_response(403)):
			with self.assertRaises(QueryBackendError) as cm:
				self._backend('bad')._make_request('GET', 'workspaces')
		self.assertIn('(403)', cm.exception.message)
		self.assertEqual(cm.exception.backend, 'api')
		self.assertEqual(cm.exception.status_code, 403)
		self.assertIn('invalid', cm.exception.message)

	def test_auth_error_is_not_swallowed_by_reads(self):
		backend = self._backend('')
		calls = {
			'list_workspaces': lambda: backend.list_workspaces(),
			'list_runners': lambda: backend.list_runners(),
			'get_workspace': lambda: backend.get_workspace('ws1'),
			'get_runner': lambda: backend.get_runner('r1', 'task'),
			'search': lambda: backend.search({}),
			'count': lambda: backend.count({}),
		}
		with mock.patch('secator.query.api._session.request', return_value=_response(401)):
			for name, call in calls.items():
				with self.subTest(call=name):
					with self.assertRaises(QueryBackendError):
						call()

	def test_other_http_errors_stay_best_effort(self):
		payload = {'items': [{'_id': 'a' * 24, 'name': 'ws'}]}
		request = mock.patch('secator.query.api._session.request', return_value=_response(500, payload))
		with request, mock.patch('secator.query.api.console') as console:
			self.assertEqual(self._backend('k').list_workspaces(), [])
			self.assertEqual(self._backend('k').search({}), [])
		self.assertEqual(console.print.call_count, 2)

	def test_update_attempts_every_write_before_raising_auth_error(self):
		backend = self._backend('k')
		docs = [{'_id': 'a' * 24}, {'_id': 'b' * 24}]
		puts = []

		def fake(method, endpoint, data=None):
			puts.append(endpoint)
			if len(puts) == 1:
				raise QueryBackendError('denied')
			return {}
		search_all = mock.patch.object(ApiBackend, '_search_all', return_value=docs)
		with search_all, mock.patch.object(ApiBackend, '_make_request', side_effect=fake):
			with self.assertRaises(QueryBackendError):
				backend._execute_update({}, {'$set': {'status': 'consumed'}})
		self.assertEqual(len(puts), 2)

	def test_ok_response_is_returned(self):
		items = [{'_id': 'a' * 24, 'name': 'ws'}]
		with mock.patch('secator.query.api._session.request', return_value=_response(200, items)):
			self.assertEqual(self._backend('k').list_workspaces(), items)

	def test_steer_poll_reports_auth_error_without_raising(self):
		from secator.ai.interactivity import RemoteBackend
		engine = mock.Mock()
		engine.search.side_effect = QueryBackendError('rejected key')
		with mock.patch('secator.rich.console') as console:
			self.assertEqual(RemoteBackend(timeout=1, query_engine=engine).poll_steers('s1'), [])
		console.print.assert_called_once()

	def test_steer_poll_stays_quiet_when_empty(self):
		from secator.ai.interactivity import RemoteBackend
		engine = mock.Mock()
		engine.search.return_value = []
		with mock.patch('secator.rich.console') as console:
			self.assertEqual(RemoteBackend(timeout=1, query_engine=engine).poll_steers('s1'), [])
		console.print.assert_not_called()


class TestWorkspaceListAuthError(unittest.TestCase):

	def test_ws_list_fails_clearly_without_a_valid_key(self):
		from secator.cli import cli
		with mock.patch('secator.query.api._session.request', return_value=_response(401)):
			with mock.patch('secator.query.api.CONFIG.addons.api.key', ''):
				result = CliRunner().invoke(cli, ['ws', 'list', '--driver', 'api'])
		self.assertEqual(result.exit_code, 1)
		self.assertIn('no API key is configured', result.output)


if __name__ == '__main__':
	unittest.main()
