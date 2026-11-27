"""Client of the worker-mode ai scenarios: dispatch one ai run to the worker and wait for it.

``python -m tests.integration.ai.worker_client <spec.json>``; the spec holds the targets, run
options and context, an optional ``revoke_when_running`` (runner names: once all of them are
RUNNING in the store, a SIGINT - the user's Ctrl-C) and the ``out`` path where the run
summary (status, items, elapsed) is written. Runs in its own process so the Celery app is
configured for the test broker from the environment, like a real client.
"""
import json
import os
import signal
import sys
import threading
import time

os.environ.setdefault('LITELLM_LOCAL_MODEL_COST_MAP', 'True')


def _guard():
	"""The model lives in the worker: any model call or outbound connection here is a bug."""
	from unittest import mock
	import litellm
	from tests.integration.ai.scripted import NetworkGuard, _forbidden
	for name in ('completion', 'acompletion', 'text_completion'):
		mock.patch.object(litellm, name, _forbidden(f'client-side litellm.{name}')).start()
	NetworkGuard(on_block=lambda addr: print(f'AI-E2E-NETWORK-BLOCKED {addr}', file=sys.stderr, flush=True)).start()


REACHED_RUNNING = threading.Event()


def _interrupt_when_running(session_id, names, timeout=120):
	"""SIGINT this process once a runner of each of ``names`` is RUNNING in the session's
	reports (json driver), so the revoke lands while those children run."""
	from pathlib import Path
	from secator.config import CONFIG
	deadline = time.monotonic() + timeout
	while time.monotonic() < deadline:
		running = set()
		for path in Path(CONFIG.dirs.reports).glob('**/report*.json'):  # a child may only have report_<name>.json
			try:
				info = json.loads(path.read_text()).get('info', {})
			except (ValueError, OSError):
				continue
			if (info.get('context') or {}).get('session_id') == session_id and info.get('status') == 'RUNNING':
				running.add(info.get('name'))
		if names <= running:
			REACHED_RUNNING.set()
			time.sleep(1)  # let them get going
			break
		time.sleep(0.3)
	os.kill(os.getpid(), signal.SIGINT)


def main(spec_path):
	from secator.config import CONFIG
	from tests.integration.ai.worker_config import apply_config
	apply_config(CONFIG)
	_guard()
	from secator.runners import Task
	from secator.template import TemplateLoader

	with open(spec_path) as f:
		spec = json.load(f)
	# The Task wrapper dispatches the ai task to its queue (as `secator x ai` does with a worker).
	task = Task(TemplateLoader(input={'type': 'task', 'name': 'ai'}), spec['targets'], run_opts=spec['opts'],
	            context=spec['context'])
	if spec.get('revoke_when_running'):  # the user's Ctrl-C: the runner revokes its Celery tasks and ends
		threading.Thread(target=_interrupt_when_running, args=(spec['context']['session_id'],
		                 set(spec['revoke_when_running'])), daemon=True).start()
	start = time.monotonic()
	error = None
	try:
		items = task.run()
	except Exception as e:  # noqa: BLE001 - reported to the test
		items, error = [], f'{type(e).__name__}: {e}'
	out = {
		'id': task.id,
		'status': task.status,
		'elapsed': time.monotonic() - start,
		'error': error,
		'items': [i.toDict() if hasattr(i, 'toDict') else i for i in items],
		'celery_ids': list(getattr(task, 'celery_ids_map', {}) or {}),
		'reached_running': REACHED_RUNNING.is_set(),
	}
	with open(spec['out'], 'w') as f:
		json.dump(out, f, default=str)


if __name__ == '__main__':
	main(sys.argv[1])
