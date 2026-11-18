import os
import signal
import threading
from pathlib import Path

from celery import signals

from secator.config import CONFIG
from secator.output_types import Info
from secator.rich import console

IDLE_TIMEOUT = CONFIG.celery.worker_kill_after_idle_seconds

# File-based state management system
STATE_DIR = Path("/tmp/celery_state")
STATE_DIR.mkdir(exist_ok=True, parents=True)


def get_lock_file_path():
	worker_name = os.environ.get("WORKER_NAME", f"unknown_{os.getpid()}")
	return Path(f"/tmp/celery_worker_{worker_name}.lock")


def set_task_running(task_id):
	"""Mark that a task is running in current worker"""
	with open(get_lock_file_path(), "w") as f:
		f.write(task_id)


def clear_task_running():
	"""Clear the task running state"""
	lock_file = get_lock_file_path()
	if lock_file.exists():
		lock_file.unlink()


def is_task_running():
	"""Check if a task is currently running"""
	return get_lock_file_path().exists()


def kill_worker(parent=False):
	"""Kill current worker using its pid by sending a SIGTERM to Celery master process."""
	worker_name = os.environ.get('WORKER_NAME', 'unknown')

	# Check if a task is running via the lock file
	if not is_task_running():
		pid = os.getppid() if parent else os.getpid()
		console.print(Info(message=f'Sending SIGTERM to worker {worker_name} with pid {pid}'))
		os.kill(pid, signal.SIGTERM)
	else:
		console.print(Info(message=f'Cancelling worker shutdown of {worker_name} since a task is running'))


def setup_idle_timer(timeout):
	"""Setup a timer to kill the worker after being idle"""
	if timeout == -1:
		return

	console.print(Info(message=f'Starting inactivity timer for {timeout} seconds ...'))
	timer = threading.Timer(timeout, kill_worker)
	timer.daemon = True  # Make sure timer is killed when worker exits
	timer.start()


def setup_logging(*args, **kwargs):
	"""Override celery's logging setup to prevent it from altering our settings.
	github.com/celery/celery/issues/1867
	"""
	pass


def capture_worker_name(sender, instance, **kwargs):
	os.environ["WORKER_NAME"] = '{0}'.format(sender)


def worker_init_handler(**kwargs):
	if IDLE_TIMEOUT != -1:
		setup_idle_timer(IDLE_TIMEOUT)


def kills_after_task(task_name):
	"""Whether the worker ends after running a task with this name."""
	return bool(CONFIG.celery.worker_kill_after_task and task_name and task_name.startswith(('secator.', 'api.')))


def in_pool_child():
	"""Whether this process is a pool child (prefork) rather than the worker's main process."""
	from billiard import current_process
	return current_process().name != 'MainProcess'


def is_eager(task):
	"""Whether the task was applied in-process by the worker's own task (a child runner run in
	sync mode): its prerun / postrun must not touch the worker's running state nor end it."""
	return task is not None and getattr(task.request, 'is_eager', False)


def task_received_handler(sender=None, request=None, **kwargs):
	"""Stop consuming once the task that will end this worker is received, so nothing else is
	delivered while it runs nor between its (late) ack and the worker's shutdown."""
	if sender is None or not kills_after_task(getattr(request, 'name', None)):
		return
	for queue in [q.name for q in sender.task_consumer.queues]:
		sender.cancel_task_queue(queue)


def task_prerun_handler(task_id, **kwargs):
	if is_eager(kwargs.get('task')):
		return

	# Mark that a task is running
	set_task_running(task_id)


def task_postrun_handler(**kwargs):
	if is_eager(kwargs.get('task')):
		return

	# Mark that no task is running
	clear_task_running()

	# Get sender name from kwargs
	sender_name = kwargs['sender'].name
	# console.print(Info(message=f'Task postrun handler --> Sender name: {sender_name}'))

	if kills_after_task(sender_name):
		worker_name = os.environ.get('WORKER_NAME', 'unknown')
		console.print(Info(message=f'Shutdown worker {worker_name} since config celery.worker_kill_after_task is set.'))
		kill_worker(parent=in_pool_child())
		return

	# Set up a new idle timer
	if IDLE_TIMEOUT != -1:
		console.print(Info(message=f'Reset inactivity timer to {IDLE_TIMEOUT} seconds'))
		setup_idle_timer(IDLE_TIMEOUT)


def task_revoked_handler(request=None, **kwargs):
	"""Handle revoked tasks by clearing the task running state"""
	console.print(Info(message='Task was revoked, clearing running state'))
	clear_task_running()

	# Set up a new idle timer
	if IDLE_TIMEOUT != -1:
		console.print(Info(message=f'Reset inactivity timer to {IDLE_TIMEOUT} seconds after task revocation'))
		setup_idle_timer(IDLE_TIMEOUT)


def worker_shutdown_handler(**kwargs):
	"""Cleanup lock files when worker shuts down"""
	lock_file = get_lock_file_path()
	if lock_file.exists():
		lock_file.unlink()


def setup_handlers():
	if CONFIG.celery.override_default_logging:
		signals.setup_logging.connect(setup_logging)

	# Register common handlers when either task‐ or idle‐based termination is enabled
	if CONFIG.celery.worker_kill_after_task or CONFIG.celery.worker_kill_after_idle_seconds != -1:
		signals.celeryd_after_setup.connect(capture_worker_name)
		signals.task_postrun.connect(task_postrun_handler)
		signals.task_prerun.connect(task_prerun_handler)
		if CONFIG.celery.worker_kill_after_task:
			signals.task_received.connect(task_received_handler)
		signals.task_revoked.connect(task_revoked_handler)
		signals.worker_ready.connect(worker_init_handler)
		signals.worker_shutdown.connect(worker_shutdown_handler)
