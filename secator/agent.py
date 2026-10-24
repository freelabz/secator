"""Pull-based runner agent: ``secator agent run --driver <api|mongodb|sqlite|local>``.

The driver is THE backend, as for ``secator x|w|s --driver``: the agent claims work
from it and the run writes its results back to it. Work is claimed through the
per-driver interface in ``secator.schedule`` (claim / heartbeat / complete / fail);
on local backends a claim fires a due schedule, on ``api`` the job server hands out
queued jobs and fires its own schedules.

Each claimed job runs in a child process (``python -m secator.agent <spec.json>``)
that builds the runner from the JSON spec in sync mode, exactly as ``secator x|w|s``
would, with the spec's drivers. While it runs, the agent heartbeats the lease; a
cancel request, a lost lease or an unreachable backend (longer than the lease TTL)
interrupts the child (SIGINT, then SIGKILL after a grace period).

``secator agent enroll`` / ``status`` only apply to the ``api`` driver, whose agents
authenticate with an enrolled credential.
"""

import ipaddress
import json
import os
import random
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import urlparse

import requests
import rich_click as click

from secator.config import CONFIG
from secator.definitions import VERSION
from secator.rich import console
from secator.schedule import BACKENDS, LeaseLost, get_backend

AGENT_FILE = os.path.join(str(CONFIG.dirs.data), 'agent.json')
CANCEL_GRACE = 60   # seconds between SIGINT and SIGKILL
IDLE_POLL = 5       # seconds between claims on local backends when idle


class Agent:

	def __init__(self, backend, name, capacity=1, allowed_cidrs=None, site_id=None):
		self.backend = backend
		self.name = name
		self.capacity = capacity
		self.allowed_cidrs = [ipaddress.ip_network(c, strict=False) for c in (allowed_cidrs or [])]
		self.site_id = site_id
		self.jobs = {}  # job_id -> supervising thread

	def run(self, once=False):
		"""Claim and supervise jobs until interrupted (or after one job if ``once``)."""
		backoff = 1
		while True:
			self.jobs = {k: t for k, t in self.jobs.items() if t.is_alive()}
			if len(self.jobs) >= self.capacity:
				time.sleep(1)
				continue
			try:
				job = self.backend.claim(self.name)
				backoff = 1
			except Exception as e:
				console.print(f'[bold orange3]Claim failed ({e}), retrying in {backoff}s[/]')
				time.sleep(backoff + random.random())
				backoff = min(backoff * 2, 60)
				continue
			if job is None:
				if self.backend.name != 'api':  # api claims long-poll server side
					time.sleep(IDLE_POLL)
				continue
			thread = threading.Thread(target=self.supervise, args=(job,), daemon=True)
			thread.start()
			self.jobs[job['job_id']] = thread
			if once:
				thread.join()
				return

	def check_spec(self, job):
		"""Return a refusal reason for a job this agent must not run, else None."""
		ctx = job['spec'].get('context') or {}
		if self.site_id and ctx.get('site_id') != self.site_id:
			return f'job is for site {ctx.get("site_id")!r}, this agent is enrolled in {self.site_id!r}'
		if self.allowed_cidrs:
			for target in job['spec'].get('targets') or []:
				if not targets_allowed([target], self.allowed_cidrs):
					return f'target {target!r} is outside the allowed CIDRs'
		return None

	def supervise(self, job):
		"""Run one job in a child process, heartbeat its lease, and report its exit."""
		job_id = job['job_id']
		refusal = self.check_spec(job)
		if refusal:
			console.print(f'[bold red]Refusing job {job_id}: {refusal}[/]')
			self.backend.fail(job, refusal)
			return

		with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as f:
			json.dump(job['spec'], f)
			spec_path = f.name
		os.chmod(spec_path, 0o600)
		env = {**os.environ, **self.backend.child_env(job)}
		console.print(f'[bold green]Starting job {job_id}[/] ({job.get("schedule") or job.get("runner", {}).get("id", "")})')
		proc = subprocess.Popen([sys.executable, '-m', 'secator.agent', spec_path], env=env)

		every = job.get('heartbeat_every', 20)
		lease_ttl = job.get('lease_ttl', 90)
		last_ok = time.time()
		stop_at = None
		cancelled = False
		try:
			while proc.poll() is None:
				reason = None
				try:
					if self.backend.heartbeat(job):
						reason = 'cancel requested'
					last_ok = time.time()
				except LeaseLost:
					reason = 'lease lost'
				except Exception as e:
					if time.time() - last_ok > lease_ttl:
						reason = f'backend unreachable for {lease_ttl}s ({e})'
				if reason and stop_at is None:
					console.print(f'[bold orange3]Stopping job {job_id}: {reason}[/]')
					cancelled = True
					stop_at = time.time()
					proc.send_signal(signal.SIGINT)
				elif stop_at and time.time() - stop_at > CANCEL_GRACE:
					proc.kill()
				try:
					proc.wait(timeout=every)
				except subprocess.TimeoutExpired:
					pass
		finally:
			os.unlink(spec_path)
		code = proc.returncode
		status = 'SUCCESS' if code == 0 else 'STOPPED' if cancelled else 'FAILURE'
		console.print(f'Job {job_id} exited with code {code} ({status})')
		self.backend.complete(job, status, exit_code=code)


def targets_allowed(targets, networks):
	"""True if every target's host (IP, CIDR, URL or hostname) resolves inside ``networks``.

	ponytail: checks the job's input targets only; targets discovered mid-run are not re-checked.
	"""
	for target in targets:
		try:
			addrs = [ipaddress.ip_network(target, strict=False)]
		except ValueError:
			host = urlparse(target if '://' in target else f'//{target}').hostname
			try:
				addrs = [ipaddress.ip_network(i[4][0]) for i in socket.getaddrinfo(host, None)] if host else []
			except (socket.gaierror, UnicodeError):
				addrs = []
			if not addrs:
				return False
		for addr in addrs:
			if not any(addr.version == n.version and addr.subnet_of(n) for n in networks):
				return False
	return True


def exec_job(spec_path):
	"""Child process entrypoint: build the runner from a JSON job spec and run it synchronously.

	Driver hooks come from ``context['drivers']`` (registered by the runner itself)."""
	from secator.runners import Scan, Task, Workflow
	from secator.template import TemplateLoader

	with open(spec_path) as f:
		spec = json.load(f)
	config = TemplateLoader(input=spec['config'])
	run_opts = dict(spec.get('run_opts') or {})
	profiles = run_opts.get('profiles') or []
	if isinstance(profiles, str):
		profiles = [p.strip() for p in profiles.split(',') if p.strip()]
	run_opts['profiles'] = [TemplateLoader(input=p) if isinstance(p, dict) else TemplateLoader(name=f'profile/{p}') for p in profiles]  # noqa: E501
	run_opts.update({'sync': True, 'print_item': True, 'print_line': True, 'print_start': True, 'print_end': True})
	context = dict(spec.get('context') or {})
	runner_cls = {'scan': Scan, 'workflow': Workflow, 'task': Task}[config.type]
	runner = runner_cls(config, inputs=spec.get('targets') or [], run_opts=run_opts, context=context)
	for _ in runner:
		pass
	return 0 if runner.status == 'SUCCESS' else 1


# ----- #
#  CLI  #
# ----- #


def load_agent_file():
	try:
		with open(AGENT_FILE) as f:
			return json.load(f)
	except FileNotFoundError:
		console.print(f'[bold red]No agent credentials at {AGENT_FILE}: run `secator agent enroll` first.[/]')
		sys.exit(1)


@click.group()
def agent():
	"""Run a pull-based agent that executes claimed jobs and due schedules."""


@agent.command()
@click.option('--url', required=True, help='Server API URL.')
@click.option('--token', required=True, help='One-time enrollment token.')
@click.option('--name', default=socket.gethostname(), help='Agent name.')
def enroll(url, token, name):
	"""Enroll this host as an agent of a job server (api driver only)."""
	resp = requests.post(f'{url.rstrip("/")}/agent/enroll', json={'token': token, 'name': name, 'version': VERSION}, timeout=30, verify=CONFIG.addons.api.force_ssl)  # noqa: E501
	if not resp.ok:
		console.print(f'[bold red]Enrollment failed: HTTP {resp.status_code} {resp.text[:200]}[/]')
		sys.exit(1)
	creds = {'url': url, 'name': name, **resp.json()}
	os.makedirs(os.path.dirname(AGENT_FILE), exist_ok=True)
	fd = os.open(AGENT_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
	with os.fdopen(fd, 'w') as f:
		json.dump(creds, f)
	console.print(f'[bold green]Enrolled agent {creds["agent_id"]} in site {creds.get("site_id")}[/] ({AGENT_FILE})')


@agent.command()
@click.option('--driver', type=click.Choice(sorted(BACKENDS)), default=None, help='Backend to pull work from and write results to [default: first configured driver, else local].')  # noqa: E501
@click.option('--name', default=None, help='Agent name, matched against schedule --agent labels [default: hostname].')
@click.option('--capacity', type=int, default=1, help='Max jobs to run in parallel.')
@click.option('--allowed-cidrs', default='', help='Comma-separated CIDRs; refuse jobs whose targets fall outside.')
@click.option('--once', is_flag=True, help='Exit after one job.')
def run(driver, name, capacity, allowed_cidrs, once):
	"""Claim and run jobs / due schedules from a backend."""
	from secator.query import QueryEngine
	driver = QueryEngine.resolve_backend(driver)
	cidrs = [c.strip() for c in allowed_cidrs.split(',') if c.strip()]
	site_id = None
	if driver == 'api':
		creds = load_agent_file()
		backend = get_backend('api', creds=creds)
		name, site_id = creds.get('name') or creds['agent_id'], creds.get('site_id')
	else:
		backend = get_backend(driver)
	a = Agent(backend, name or socket.gethostname(), capacity, cidrs, site_id)
	console.print(f'Agent [bold]{a.name}[/] pulling from the [bold]{driver}[/] backend (capacity {capacity})')
	a.run(once=once)


@agent.command()
def status():
	"""Show this agent as seen by the server (api driver only)."""
	backend = get_backend('api', creds=load_agent_file())
	console.print_json(backend.request('GET', 'agent/self').text)


if __name__ == '__main__':
	sys.exit(exec_job(sys.argv[1]))
