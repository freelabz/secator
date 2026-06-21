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

# Eviction flag. On worker shutdown (e.g. a K8s pod SIGTERM eviction) we raise this flag; the
# running task's monitor thread (in the prefork child, a separate process) polls it via a file
# and stops early, returning partial results so the surrounding chord proceeds — instead of the
# task hanging until the broker visibility timeout redelivers it (hours, on the long pool).
SHUTDOWN_FLAG = STATE_DIR / "worker_shutdown"


def is_worker_shutting_down():
	"""True once the worker has begun shutting down (set by worker_shutting_down_handler)."""
	return SHUTDOWN_FLAG.exists()


def clear_shutdown_flag():
	"""Remove the eviction flag (called on worker boot to drop any stale flag)."""
	if SHUTDOWN_FLAG.exists():
		SHUTDOWN_FLAG.unlink()


def worker_shutting_down_handler(**kwargs):
	"""Raise the eviction flag so the in-flight task's monitor stops it early and returns."""
	try:
		SHUTDOWN_FLAG.write_text("1")
	except Exception:
		pass


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


def task_prerun_handler(task_id, **kwargs):
	# Mark that a task is running
	set_task_running(task_id)


def task_postrun_handler(**kwargs):
	# Mark that no task is running
	clear_task_running()

	# Get sender name from kwargs
	sender_name = kwargs['sender'].name
	# console.print(Info(message=f'Task postrun handler --> Sender name: {sender_name}'))

	if CONFIG.celery.worker_kill_after_task and (sender_name.startswith('secator.') or sender_name.startswith('api.')):
		worker_name = os.environ.get('WORKER_NAME', 'unknown')
		console.print(Info(message=f'Shutdown worker {worker_name} since config celery.worker_kill_after_task is set.'))
		kill_worker(parent=True)
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

	# Eviction handling (always on): clear any stale flag from a previous worker in this pod,
	# and raise it on shutdown so the in-flight task stops early and lets its chord proceed.
	clear_shutdown_flag()
	signals.worker_shutting_down.connect(worker_shutting_down_handler)

	# Register common handlers when either task‐ or idle‐based termination is enabled
	if CONFIG.celery.worker_kill_after_task or CONFIG.celery.worker_kill_after_idle_seconds != -1:
		signals.celeryd_after_setup.connect(capture_worker_name)
		signals.task_postrun.connect(task_postrun_handler)
		signals.task_prerun.connect(task_prerun_handler)
		signals.task_revoked.connect(task_revoked_handler)
		signals.worker_ready.connect(worker_init_handler)
		signals.worker_shutdown.connect(worker_shutdown_handler)
