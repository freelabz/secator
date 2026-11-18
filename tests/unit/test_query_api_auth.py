"""The api query backend surfaces a missing / rejected API key as an error, not an empty result."""
import unittest
from unittest import mock

from click.testing import CliRunner

from secator.query.api import ApiAuthError, ApiBackend


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


class TestApiAuthErrors(unittest.TestCase):

	def _backend(self, key):
		backend = ApiBackend(workspace_id='ws1')
		backend.api_key = key
		return backend

	def test_missing_key_401_explains_how_to_configure_one(self):
		with mock.patch('secator.query.api.requests.request', return_value=_response(401)):
			with self.assertRaises(ApiAuthError) as cm:
				self._backend('')._make_request('GET', 'workspaces')
		self.assertIn('no API key is configured', cm.exception.message)
		self.assertIn('addons.api.key', cm.exception.message)

	def test_rejected_key_403_says_the_key_is_invalid(self):
		with mock.patch('secator.query.api.requests.request', return_value=_response(403)):
			with self.assertRaises(ApiAuthError) as cm:
				self._backend('bad')._make_request('GET', 'workspaces')
		self.assertIn('(403)', cm.exception.message)
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
		with mock.patch('secator.query.api.requests.request', return_value=_response(401)):
			for name, call in calls.items():
				with self.subTest(call=name):
					with self.assertRaises(ApiAuthError):
						call()

	def test_other_http_errors_stay_best_effort(self):
		with mock.patch('secator.query.api.requests.request', return_value=_response(500)):
			self.assertEqual(self._backend('k').list_workspaces(), [])
			self.assertEqual(self._backend('k').search({}), [])

	def test_ok_response_is_returned(self):
		items = [{'_id': 'a' * 24, 'name': 'ws'}]
		with mock.patch('secator.query.api.requests.request', return_value=_response(200, items)):
			self.assertEqual(self._backend('k').list_workspaces(), items)


class TestWorkspaceListAuthError(unittest.TestCase):

	def test_ws_list_fails_clearly_without_a_valid_key(self):
		from secator.cli import cli
		with mock.patch('secator.query.api.requests.request', return_value=_response(401)):
			with mock.patch('secator.query.api.CONFIG.addons.api.key', ''):
				result = CliRunner().invoke(cli, ['ws', 'list', '--driver', 'api'])
		self.assertNotEqual(result.exit_code, 0)
		self.assertIsInstance(result.exception, SystemExit)
		self.assertIn('no API key is configured', result.output)


if __name__ == '__main__':
	unittest.main()
