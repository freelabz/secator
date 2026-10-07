"""Unit tests for the pull-based agent (secator.agent)."""
import ipaddress
import json
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, mock_open, patch

from secator import agent as agent_mod
from secator.agent import Agent, exec_job, targets_allowed
from secator.schedule import ApiBackend, LocalBackend, make_schedule


def _job(site_id='site-a', targets=None):
	return {
		'job_id': 'j1',
		'lease_id': 'l1',
		'lease_ttl': 90,
		'heartbeat_every': 0,
		'runner': {'type': 'task', 'id': 'a' * 24},
		'spec': {
			'config': {'name': 'httpx', 'type': 'task'},
			'targets': targets or ['10.0.0.5'],
			'run_opts': {},
			'context': {'task_id': 'a' * 24, 'workspace_id': 'b' * 24, 'site_id': site_id, 'drivers': ['api']},
		},
		'api': {'url': 'https://server/api', 'run_token': 'rt_x'},
	}


def _resp(status=200, body=None):
	r = MagicMock()
	r.status_code = status
	r.json.return_value = body or {}
	r.raise_for_status.return_value = None
	return r


class TestTargetsAllowed(unittest.TestCase):

	def test_ip_cidr_url_and_host(self):
		nets = [ipaddress.ip_network('10.0.0.0/8')]
		self.assertTrue(targets_allowed(['10.1.2.3', '10.2.0.0/16', 'http://10.0.0.1:8080/x', '10.0.0.9:22'], nets))
		self.assertFalse(targets_allowed(['192.168.1.1'], nets))
		self.assertFalse(targets_allowed(['10.0.0.0/7'], nets))
		with patch.object(agent_mod.socket, 'getaddrinfo', return_value=[(0, 0, 0, '', ('10.9.9.9', 0))]):
			self.assertTrue(targets_allowed(['intranet.local'], nets))
		with patch.object(agent_mod.socket, 'getaddrinfo', side_effect=agent_mod.socket.gaierror):
			self.assertFalse(targets_allowed(['nope.invalid'], nets))


def _proc(*returncodes):
	"""A fake child process whose poll() yields ``returncodes`` in turn."""
	proc = MagicMock(pid=42, returncode=None)
	polls = iter(returncodes)

	def poll():
		proc.returncode = next(polls)
		return proc.returncode
	proc.poll.side_effect = poll
	proc.wait.side_effect = subprocess.TimeoutExpired('x', 0)
	return proc


def _api_agent(**kw):
	backend = ApiBackend(creds={'url': 'https://server/api', 'agent_id': 'ag', 'secret': 's3cret'})
	return Agent(backend, 'ag', site_id='site-a', **kw)


@patch.object(agent_mod.time, 'sleep')
@patch('secator.schedule.time.sleep')
class TestSupervise(unittest.TestCase):

	def test_refuses_job_for_another_site(self, *_):
		a = _api_agent()
		with patch.object(ApiBackend, 'request', return_value=_resp()) as req, patch.object(agent_mod.subprocess, 'Popen') as popen:  # noqa: E501
			a.supervise(_job(site_id='site-b'))
		popen.assert_not_called()
		self.assertEqual(req.call_args.args[:2], ('POST', 'agent/jobs/j1/fail'))

	def test_refuses_targets_outside_allowed_cidrs(self, *_):
		a = _api_agent(allowed_cidrs=['10.0.0.0/8'])
		with patch.object(ApiBackend, 'request', return_value=_resp()) as req, patch.object(agent_mod.subprocess, 'Popen') as popen:  # noqa: E501
			a.supervise(_job(targets=['8.8.8.8']))
		popen.assert_not_called()
		self.assertIn('outside the allowed CIDRs', req.call_args.kwargs['json']['error'])

	def test_cancel_from_heartbeat_interrupts_child_and_completes(self, *_):
		a = _api_agent()
		proc = _proc(None, None, 130)
		calls = []

		def request(method, path, **kwargs):
			calls.append((path, kwargs.get('json')))
			return _resp(body={'lease_ttl': 90, 'cancel': True}) if path.endswith('heartbeat') else _resp()

		with patch.object(ApiBackend, 'request', side_effect=request), patch.object(agent_mod.subprocess, 'Popen', return_value=proc) as popen:  # noqa: E501
			a.supervise(_job())
		env = popen.call_args.kwargs['env']
		self.assertEqual(env['SECATOR_ADDONS_API_KEY'], 'rt_x')
		self.assertEqual(env['SECATOR_ADDONS_API_HEADER_NAME'], 'Run')
		proc.send_signal.assert_called_once_with(signal.SIGINT)
		self.assertEqual(calls[-1][0], 'agent/jobs/j1/complete')
		self.assertEqual(calls[-1][1], {'lease_id': 'l1', 'exit_code': 130, 'final_status': 'STOPPED', 'error': None})

	def test_lease_lost_interrupts_child(self, *_):
		a = _api_agent()
		proc = _proc(None, 1)
		with patch.object(ApiBackend, 'request', side_effect=[_resp(409), _resp()]), patch.object(agent_mod.subprocess, 'Popen', return_value=proc):  # noqa: E501
			a.supervise(_job())
		proc.send_signal.assert_called_once_with(signal.SIGINT)

	def test_local_backend_schedule_run(self, *_):
		"""A due schedule on a local backend is fired, run, heartbeated and completed by the agent."""
		with tempfile.TemporaryDirectory() as tmp:
			backend = LocalBackend(path=f'{tmp}/schedules.json')
			s = make_schedule({'name': 'httpx', 'type': 'task'}, ['10.0.0.5'], {}, {'drivers': ['json']}, '* * * * *', now=0)  # noqa: E501
			backend.add_schedule(s)
			a = Agent(backend, 'laptop')
			job = backend.claim('laptop')
			with patch.object(agent_mod.subprocess, 'Popen', return_value=_proc(None, 0)) as popen:
				a.supervise(job)
			self.assertNotIn('SECATOR_ADDONS_API_KEY', popen.call_args.kwargs['env'])
			stored = backend.list_schedules()[0]
			self.assertEqual(stored['last_status'], 'SUCCESS')
			self.assertIsNone(stored['lease_id'])


class TestExecJob(unittest.TestCase):

	def test_runner_attaches_to_precreated_id(self):
		spec = _job()['spec']
		spec['run_opts'] = {'profiles': ['aggressive'], 'rate_limit': 5}
		fake_runner = MagicMock(status='SUCCESS')
		fake_runner.__iter__.return_value = iter([])
		with patch('builtins.open', mock_open(read_data=json.dumps(spec))), \
			patch('secator.runners.Task', return_value=fake_runner) as task_cls, \
			patch('secator.template.TemplateLoader', return_value=MagicMock(type='task')):
			self.assertEqual(exec_job('spec.json'), 0)
		kwargs = task_cls.call_args.kwargs
		self.assertEqual(kwargs['context']['task_id'], 'a' * 24)
		self.assertEqual(kwargs['context']['drivers'], ['api'])
		self.assertTrue(kwargs['run_opts']['sync'])
		self.assertEqual(kwargs['run_opts']['rate_limit'], 5)
		self.assertEqual(len(kwargs['run_opts']['profiles']), 1)


if __name__ == '__main__':
	unittest.main()
