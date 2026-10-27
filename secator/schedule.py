"""Scheduled runs and the per-driver work queue used by ``secator agent``.

A schedule is a stored runner spec (config, targets, run_opts, context) plus a cron
expression and an optional agent label. There is no beat process: an agent's claim
fires a due schedule atomically, then the agent runs it and heartbeats / completes
the lease. Every driver implements the same small interface (``Backend``):

	add_schedule(schedule) / list_schedules()
	claim(agent, now)           -> job dict or None
	heartbeat(job, now)         -> True if a cancel was requested; raises LeaseLost
	complete(job, status, ...)  -> release the lease, record the outcome
	fail(job, error)            -> complete as FAILURE (job refused / not started)

Rules, identical for every local backend (``local``, ``sqlite``, ``mongodb``):

- Missed fires: a due schedule fires once and ``next_run`` rolls forward to the next
  cron time after *now* (no catch-up storm).
- Overlap: a schedule whose previous run still holds its lease is not claimed; fires
  that came due during that run are skipped (``next_run`` rolls forward at complete).
- Label: a schedule with an ``agent`` label is only claimable by that agent; an
  unlabelled one by any agent.

The ``api`` backend speaks the job server's agent protocol; firing schedules happens
server side under the same rules.
"""

import fcntl
import json
import os
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from secator.config import CONFIG

LEASE_TTL = 90        # seconds; renewed by heartbeats
HEARTBEAT_EVERY = 20


class LeaseLost(Exception):
	"""The job's lease was reaped or re-leased: the run must stop."""


# ---- #
# Cron #
# ---- #


def _crontab(cron):
	"""Parse a 5-field cron expression with celery's parser (a core dependency).

	Note: when both day-of-month and day-of-week are restricted, celery requires both
	to match (classic cron matches either)."""
	from celery.schedules import crontab
	fields = cron.split()
	if len(fields) != 5:
		raise ValueError(f'invalid cron expression {cron!r}: expected 5 fields')
	minute, hour, dom, month, dow = fields
	return crontab(minute=minute, hour=hour, day_of_month=dom, month_of_year=month, day_of_week=dow)


def validate_cron(cron):
	_crontab(cron)  # raises ValueError
	return cron


def next_run(cron, after):
	"""Epoch seconds of the first cron time strictly after ``after`` (epoch seconds)."""
	t = datetime.fromtimestamp(after, timezone.utc)
	ct = _crontab(cron)
	ct.nowfun = lambda: t
	return (t + ct.remaining_estimate(t)).timestamp()


def make_schedule(config, targets, run_opts, context, cron, agent=None, name=None, now=None):
	"""A new schedule document (JSON-safe)."""
	now = time.time() if now is None else now
	return {
		'id': uuid.uuid4().hex,
		'name': name or config.get('name'),
		'cron': validate_cron(cron),
		'agent': agent or None,
		'enabled': True,
		'spec': {'config': config, 'targets': [targets] if isinstance(targets, str) else list(targets), 'run_opts': run_opts, 'context': context},  # noqa: E501
		'next_run': next_run(cron, now),
		'last_run': None,
		'last_status': None,
		'lease_id': None,
		'leased_until': 0,
		'claimed_by': None,
		'created_at': now,
	}


# ----------------------------------------- #
# Shared semantics (pure functions on dicts) #
# ----------------------------------------- #


def claimable(s, agent, now):
	return (
		s.get('enabled', True)
		and s['next_run'] <= now
		and (s.get('leased_until') or 0) < now
		and s.get('agent') in (None, agent)
	)


def claim_update(s, agent, now):
	"""Fields set when ``agent`` fires schedule ``s`` at ``now``."""
	return {
		'next_run': next_run(s['cron'], now),  # roll forward: missed fires collapse into this one
		'lease_id': uuid.uuid4().hex,
		'leased_until': now + LEASE_TTL,
		'claimed_by': agent,
		'last_run': now,
		'last_status': 'RUNNING',
	}


def complete_update(s, status, error, now):
	update = {'lease_id': None, 'leased_until': 0, 'last_status': status, 'last_error': error}
	if s['next_run'] <= now:  # fires that came due during the run are skipped (no overlap)
		update['next_run'] = next_run(s['cron'], now)
	return update


def to_job(s):
	return {
		'job_id': s['id'],
		'lease_id': s['lease_id'],
		'lease_ttl': LEASE_TTL,
		'heartbeat_every': HEARTBEAT_EVERY,
		'schedule': s['name'],
		'spec': s['spec'],
	}


class Backend:
	"""Per-driver claim / heartbeat / complete interface (see module docstring)."""

	name = None

	def add_schedule(self, schedule):
		raise NotImplementedError

	def list_schedules(self):
		raise NotImplementedError

	def claim(self, agent, now=None):
		raise NotImplementedError

	def heartbeat(self, job, now=None):
		raise NotImplementedError

	def complete(self, job, status, exit_code=None, error=None, now=None):
		raise NotImplementedError

	def fail(self, job, error):
		return self.complete(job, 'FAILURE', error=error)

	def child_env(self, job):
		"""Extra environment for the child process running ``job``."""
		return {}


class _TxBackend(Backend):
	"""Backends whose whole schedule set is read and written inside one exclusive
	transaction (``_tx``), which makes claim / heartbeat / complete atomic."""

	@contextmanager
	def _tx(self):
		raise NotImplementedError

	def add_schedule(self, schedule):
		with self._tx() as rows:
			rows.append(schedule)
		return schedule['id']

	def list_schedules(self):
		with self._tx() as rows:
			return [dict(s) for s in rows]

	def claim(self, agent, now=None):
		now = time.time() if now is None else now
		with self._tx() as rows:
			for s in sorted(rows, key=lambda s: s['next_run']):
				if claimable(s, agent, now):
					s.update(claim_update(s, agent, now))
					return to_job(s)
		return None

	def _leased(self, rows, job):
		s = next((s for s in rows if s['id'] == job['job_id']), None)
		if not s or s.get('lease_id') != job['lease_id']:
			raise LeaseLost(job['job_id'])
		return s

	def heartbeat(self, job, now=None):
		now = time.time() if now is None else now
		with self._tx() as rows:
			self._leased(rows, job)['leased_until'] = now + LEASE_TTL
		return False

	def complete(self, job, status, exit_code=None, error=None, now=None):
		now = time.time() if now is None else now
		with self._tx() as rows:
			try:
				s = self._leased(rows, job)
			except LeaseLost:
				return  # already reaped / re-leased: idempotent
			s.update(complete_update(s, status, error, now))


class LocalBackend(_TxBackend):
	"""``local`` driver: a JSON file in the data dir, serialized with an exclusive file lock."""

	name = 'local'

	def __init__(self, path=None):
		self.path = Path(path or Path(CONFIG.dirs.data) / 'schedules.json')

	@contextmanager
	def _tx(self):
		self.path.parent.mkdir(parents=True, exist_ok=True)
		with open(self.path.with_suffix('.lock'), 'w') as lock:
			fcntl.flock(lock, fcntl.LOCK_EX)
			try:
				rows = json.loads(self.path.read_text()) if self.path.exists() else []
				yield rows
				tmp = self.path.with_suffix('.tmp')
				tmp.write_text(json.dumps(rows))
				os.replace(tmp, self.path)
			finally:
				fcntl.flock(lock, fcntl.LOCK_UN)


class SqliteBackend(_TxBackend):
	"""``sqlite`` driver: a ``schedules`` table in the driver's database, under BEGIN IMMEDIATE."""

	name = 'sqlite'

	def __init__(self, db_path=None):
		import sqlite3
		from secator.hooks.sqlite import _get_db_path
		path = Path(db_path or _get_db_path())
		path.parent.mkdir(parents=True, exist_ok=True)
		self.conn = sqlite3.connect(str(path), timeout=CONFIG.addons.sqlite.busy_timeout_ms / 1000, isolation_level=None, check_same_thread=False)  # noqa: E501
		self.conn.execute('CREATE TABLE IF NOT EXISTS schedules (id TEXT PRIMARY KEY, data TEXT)')

	@contextmanager
	def _tx(self):
		self.conn.execute('BEGIN IMMEDIATE')
		try:
			rows = [json.loads(d) for (d,) in self.conn.execute('SELECT data FROM schedules')]
			before = {s['id']: json.dumps(s, sort_keys=True) for s in rows}
			yield rows
			for s in rows:
				data = json.dumps(s, sort_keys=True)
				if before.get(s['id']) != data:
					self.conn.execute('INSERT OR REPLACE INTO schedules (id, data) VALUES (?, ?)', (s['id'], data))
			self.conn.execute('COMMIT')
		except BaseException:
			self.conn.execute('ROLLBACK')
			raise


class MongodbBackend(Backend):
	"""``mongodb`` driver: a ``runner_schedules`` collection; claims are compare-and-set
	``find_one_and_update`` calls, so concurrent agents never fire a schedule twice."""

	name = 'mongodb'

	def __init__(self, collection=None):
		if collection is None:
			from secator.hooks.mongodb import get_mongodb_client
			collection = get_mongodb_client().main.runner_schedules
		self.col = collection

	def add_schedule(self, schedule):
		self.col.insert_one({**schedule, '_id': schedule['id']})
		return schedule['id']

	def list_schedules(self):
		return [{k: v for k, v in s.items() if k != '_id'} for s in self.col.find({})]

	def claim(self, agent, now=None):
		now = time.time() if now is None else now
		due = {
			'enabled': True, 'next_run': {'$lte': now}, 'leased_until': {'$lt': now},
			'agent': {'$in': [None, agent]},
		}
		for s in self.col.find(due).sort('next_run', 1):
			# Compare-and-set on the next_run we read: only one agent wins this fire.
			won = self.col.find_one_and_update(
				{**due, '_id': s['_id'], 'next_run': s['next_run']},
				{'$set': claim_update(s, agent, now)},
				return_document=True,
			)
			if won:
				return to_job(won)
		return None

	def heartbeat(self, job, now=None):
		now = time.time() if now is None else now
		res = self.col.update_one({'_id': job['job_id'], 'lease_id': job['lease_id']}, {'$set': {'leased_until': now + LEASE_TTL}})  # noqa: E501
		if not res.matched_count:
			raise LeaseLost(job['job_id'])
		return False

	def complete(self, job, status, exit_code=None, error=None, now=None):
		now = time.time() if now is None else now
		s = self.col.find_one({'_id': job['job_id'], 'lease_id': job['lease_id']})
		if s:
			self.col.update_one({'_id': s['_id'], 'lease_id': job['lease_id']}, {'$set': complete_update(s, status, error, now)})  # noqa: E501


class ApiBackend(Backend):
	"""``api`` driver: the job server owns the queue and fires schedules on claim.

	Schedules are created / listed with the user's api key (``addons.api``); the agent
	protocol (claim / heartbeat / complete / fail) uses the enrolled agent credential
	(``secator agent enroll``) and hands each job a job-scoped run token."""

	name = 'api'
	PROTOCOL_VERSION = '1'
	CLAIM_TIMEOUT = 35  # the server holds a claim for at most ~25s

	def __init__(self, creds=None):
		self.creds = creds

	@property
	def url(self):
		return self.creds['url'].rstrip('/')

	def request(self, method, path, timeout=30, **kwargs):
		import requests
		headers = {
			'Authorization': f'Agent {self.creds["agent_id"]}.{self.creds["secret"]}',
			'X-Secator-Agent-Protocol': self.PROTOCOL_VERSION,
		}
		return requests.request(method, f'{self.url}/{path.lstrip("/")}', headers=headers, timeout=timeout, verify=CONFIG.addons.api.force_ssl, **kwargs)  # noqa: E501

	# Schedules (user api key)

	def _resolve_label(self, label):
		"""``<site>`` or ``<site>/<agent>`` -> (site_id, agent_name)."""
		from secator.hooks.api import _make_request
		site_name, _, agent_name = label.partition('/')
		sites = _make_request('GET', 'sites') or []
		site = next((s for s in sites if site_name in (s.get('name'), s.get('_id'))), None)
		if not site:
			raise ValueError(f'no site named {site_name!r} (see the remote sites settings)')
		return site['_id'], agent_name or None

	def add_schedule(self, schedule):
		from secator.hooks.api import _make_request
		spec = schedule['spec']
		body = {
			'name': schedule['name'],
			'frequency': 'custom',
			'cron': schedule['cron'],
			'targets': spec['targets'],
			'run_opts': spec['run_opts'],
			'config': spec['config'],
			'context': {k: v for k, v in spec['context'].items() if k in ('workspace_id', 'workspace_name')},
		}
		if schedule.get('agent'):
			body['site_id'], body['agent_name'] = self._resolve_label(schedule['agent'])
		result = _make_request('POST', 'schedules', body)
		return (result or {}).get('_id')

	def list_schedules(self):
		from secator.hooks.api import _make_request

		def ts(value):
			return datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp() if value else None

		items = (_make_request('GET', 'schedules') or {}).get('items', [])
		return [{
			'id': s.get('_id'),
			'name': s.get('name'),
			'cron': s.get('cron') or s.get('frequency'),
			'agent': '/'.join(x for x in (s.get('site_name') or s.get('site_id'), s.get('agent_name')) if x) or None,
			'enabled': s.get('enabled', True),
			'next_run': ts(s.get('next_run')),
			'last_run': ts(s.get('last_run')),
			'last_status': s.get('last_status'),
		} for s in items]

	# Agent protocol (agent credential)

	def claim(self, agent=None, now=None):
		from secator.definitions import VERSION
		resp = self.request('POST', 'agent/claim', json={'version': VERSION}, timeout=self.CLAIM_TIMEOUT)
		if resp.status_code == 204:
			return None
		if resp.status_code == 426:
			from secator.rich import console
			console.print(f'[bold red]Server requires secator {resp.json().get("required_version")}, this agent runs {VERSION}. Retrying in 60s.[/]')  # noqa: E501
			time.sleep(60)
			return None
		resp.raise_for_status()
		return resp.json()

	def heartbeat(self, job, now=None):
		resp = self.request('POST', f'agent/jobs/{job["job_id"]}/heartbeat', json={'lease_id': job['lease_id']})
		if resp.status_code == 409:
			raise LeaseLost(job['job_id'])
		resp.raise_for_status()
		return bool(resp.json().get('cancel'))

	def _report(self, job, action, body):
		"""POST complete / fail, retrying with jittered backoff (idempotent on lease_id)."""
		import random
		import requests
		for attempt in range(6):
			try:
				if self.request('POST', f'agent/jobs/{job["job_id"]}/{action}', json={'lease_id': job['lease_id'], **body}).status_code < 500:  # noqa: E501
					return
			except requests.RequestException:
				pass
			time.sleep(2 ** attempt + random.random())

	def complete(self, job, status, exit_code=None, error=None, now=None):
		self._report(job, 'complete', {'exit_code': exit_code, 'final_status': status, 'error': error})

	def fail(self, job, error):
		self._report(job, 'fail', {'error': error})

	def child_env(self, job):
		return {
			'SECATOR_ADDONS_API_URL': (job.get('api') or {}).get('url') or self.url,
			'SECATOR_ADDONS_API_HEADER_NAME': 'Run',
			'SECATOR_ADDONS_API_KEY': job['api']['run_token'],
		}


BACKENDS = {'local': LocalBackend, 'sqlite': SqliteBackend, 'mongodb': MongodbBackend, 'api': ApiBackend}


def get_backend(driver, **kwargs):
	"""The schedule / work-queue backend for a driver (``secator x|w|s --driver`` names)."""
	if driver not in BACKENDS:
		raise ValueError(f'driver {driver!r} has no schedule backend (choices: {", ".join(BACKENDS)})')
	return BACKENDS[driver](**kwargs)
