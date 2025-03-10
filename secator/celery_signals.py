import os
import signal
import sys
import threading
from pathlib import Path

from celery import signals

from secator.config import CONFIG
from secator.output_types import Info
from secator.rich import console

IDLE_TIMEOUT = CONFIG.celery.worker_kill_after_idle_seconds
IN_CELERY_WORKER_PROCESS = sys.argv and ('secator.celery.app' in sys.argv or 'worker' in sys.argv)

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


def maybe_override_logging():
    def decorator(func):
        if CONFIG.celery.override_default_logging:
            return signals.setup_logging.connect(func)
        else:
            return func
    return decorator


@maybe_override_logging()
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

    if CONFIG.celery.worker_kill_after_task and sender_name.startswith('secator.'):
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
    signals.celeryd_after_setup.connect(capture_worker_name)
    signals.setup_logging.connect(setup_logging)
    signals.task_prerun.connect(task_prerun_handler)
    signals.task_postrun.connect(task_postrun_handler)
    signals.task_revoked.connect(task_revoked_handler)
    signals.worker_ready.connect(worker_init_handler)
    signals.worker_shutdown.connect(worker_shutdown_handler)
