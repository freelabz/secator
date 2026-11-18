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


def get_running_task_id():
	"""Id of the task marked as running in this worker, or None."""
	try:
		return get_lock_file_path().read_text() or None
	except OSError:
		return None


def kills_after_task(task_name):
	"""Whether this task ends the worker (``celery.worker_kill_after_task``)."""
	return bool(CONFIG.celery.worker_kill_after_task) and bool(task_name) and (
		task_name.startswith('secator.') or task_name.startswith('api.'))


def in_pool_child():
	"""Whether this process is a prefork pool child. Other pools (gevent, threads, solo) run
	tasks in the worker's main process."""
	from billiard import current_process
	return current_process().name != 'MainProcess'


def kill_worker(parent=False):
	"""Kill current worker using its pid by sending a SIGTERM to Celery master process."""
	worker_name = os.environ.get('WORKER_NAME', 'unknown')

	# Check if a task is running via the lock file
	if not is_task_running():
		pid = os.getppid() if parent else os.getpid()
		console.print(Info(message=f'Sending SIGTERM to worker {worker_name} with pid {pid}'))
		os.kill(pid, signal.SIGTERM)
		return True
	console.print(Info(message=f'Cancelling worker shutdown of {worker_name} since a task is running'))
	return False


_shutdown_requested = False


def shutdown_after_task():
	"""Stop the worker once its task is over (``celery.worker_kill_after_task``), at most once."""
	global _shutdown_requested
	if _shutdown_requested:
		return
	worker_name = os.environ.get('WORKER_NAME', 'unknown')
	console.print(Info(message=f'Shutdown worker {worker_name} since config celery.worker_kill_after_task is set.'))
	# The worker's main process is this one, unless the task ran in a prefork pool child.
	# Only a signal actually sent counts: a cancelled attempt (a task is running) may be retried.
	_shutdown_requested = kill_worker(parent=in_pool_child())


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


def task_prerun_handler(task_id, **kwargs):
	# An eager child task (applied in-process by the task this worker runs) must not replace
	# the running task's id in the marker.
	task = kwargs.get('task')
	if task is not None and getattr(task.request, 'is_eager', False):
		return
	# Mark that a task is running
	set_task_running(task_id)


def task_received_handler(sender=None, request=None, **kwargs):
	"""Stop consuming as soon as the task that will end this worker is received.

	Runs in the worker's consumer (its main process, whatever the pool). With
	``celery.worker_kill_after_task`` the worker runs exactly one task: cancelling its queue
	consumers here means nothing else is delivered while that task runs, nor between its
	(late) ack and the worker's shutdown.
	"""
	if sender is None or request is None or not kills_after_task(getattr(request, 'name', None)):
		return
	for queue in [q.name for q in getattr(sender.task_consumer, 'queues', [])]:
		sender.cancel_task_queue(queue)


def task_postrun_handler(**kwargs):
	# A task applied eagerly (a child runner run in sync mode inside the task this worker is
	# executing) also fires task_postrun, in the same process. It must neither clear the
	# running-task marker nor trigger kill-after-task: the outer task is still running.
	task = kwargs.get('task')
	if task is not None and getattr(task.request, 'is_eager', False):
		return

	# Mark that no task is running
	clear_task_running()

	# Get sender name from kwargs
	sender_name = kwargs['sender'].name
	# console.print(Info(message=f'Task postrun handler --> Sender name: {sender_name}'))

	if kills_after_task(sender_name):
		shutdown_after_task()
		return

	# Set up a new idle timer
	if IDLE_TIMEOUT != -1:
		console.print(Info(message=f'Reset inactivity timer to {IDLE_TIMEOUT} seconds'))
		setup_idle_timer(IDLE_TIMEOUT)


def task_revoked_handler(request=None, **kwargs):
	"""Handle revoked tasks by clearing the task running state"""
	# A revoked task that is not the one this worker runs (e.g. a revoked message discarded on
	# arrival) leaves the running task's state alone.
	task_id = getattr(request, 'id', None)
	running_id = get_running_task_id()
	if running_id and task_id and running_id != task_id:
		return
	console.print(Info(message='Task was revoked, clearing running state'))
	clear_task_running()

	# A revoked task does not always reach task_postrun (a terminated prefork child never does):
	# the worker's own task being revoked still ends the worker under kill-after-task.
	sender = kwargs.get('sender')
	if running_id and kills_after_task(getattr(sender, 'name', None)):
		shutdown_after_task()
		return

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
