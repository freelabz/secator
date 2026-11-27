"""Client of tests/unit/test_revoked_runners_worker.py: ``python client.py <scenario>``.

Starts a run on the worker and stops it once its commands run. In its own process, so that the
Celery app is configured for the test broker from the environment, like a real client.
"""
import subprocess
import sys
import threading
import time

from secator.celery import app, revoke_task
from secator.runners import Task, Workflow
from secator.template import TemplateLoader

SLEEPS = ['120.7', '121.3']  # odd durations, to find the commands' processes


def wait_for_commands():
	for _ in range(120):
		ps = subprocess.run(['ps', '-eo', 'args'], capture_output=True, text=True).stdout.splitlines()
		if all(f'sleep {s}' in ps for s in SLEEPS):
			return
		time.sleep(0.5)
	raise TimeoutError('the commands did not start')


def chunked():
	"""A chunked task, stopped from another thread."""
	config = TemplateLoader(input={'type': 'task', 'name': 'revoke_sleep'})
	task = Task(config, SLEEPS, run_opts={'sync': False, 'print_item': False}, context={'drivers': ['json']})
	threading.Thread(target=lambda: (wait_for_commands(), task.stop())).start()
	task.run()


def revoke_id():
	"""A chunked task, revoked by its task id (no client polls it, so only revoke_task can stop its chunks)."""
	config = TemplateLoader(input={'type': 'task', 'name': 'revoke_sleep'})
	task = Task(config, SLEEPS, run_opts={'sync': False, 'no_poll': True}, context={'drivers': ['json']})
	task.run()
	wait_for_commands()
	revoke_task(task.celery_result.id)


def chunk_fails():
	"""A chunked task one chunk of which raises."""
	config = TemplateLoader(input={'type': 'task', 'name': 'revoke_sleep'})
	Task(config, ['1', 'boom'], run_opts={'sync': False, 'print_item': False}, context={'drivers': ['json']}).run()


def workflow():
	"""A workflow running a chunked task, revoked by the id its context records (no client polls it)."""
	config = TemplateLoader(input={'type': 'workflow', 'name': 'revoke_flow', 'tasks': {'revoke_sleep': {}}})
	workflow = Workflow(config, SLEEPS, run_opts={'sync': False, 'no_poll': True}, context={'drivers': ['json']})
	workflow.run()
	wait_for_commands()
	revoke_task(workflow.context['celery_id'])


def batch():
	"""A task running its children in-process, in parallel threads: revoke it."""
	result = app.send_task('tests.run_batch_children', args=[SLEEPS], queue='revoke-test')
	wait_for_commands()
	revoke_task(result.id)


if __name__ == '__main__':
	{'chunked': chunked, 'revoke_id': revoke_id, 'chunk_fails': chunk_fails, 'workflow': workflow,
	 'batch': batch}[sys.argv[1]]()
