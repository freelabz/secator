import os
import signal
import threading

from celery import signals

from secator.config import CONFIG
from secator.output_types import Info
from secator.rich import console


IDLE_TIMEOUT = CONFIG.celery.worker_kill_after_idle_seconds
TASK_IN_PROGRESS = False


def kill_worker():
	""""Kill current worker using it's pid by sending a SIGTERM to Celery master process."""
	worker_name = os.environ['WORKER_NAME']
	if not TASK_IN_PROGRESS:
		pid = os.getpid()
		console.print(Info(message=f'Sending SIGTERM to worker {worker_name} with pid {pid}'))
		os.kill(pid, signal.SIGTERM)
	else:
		console.print(Info(message=f'Cancelling worker shutdown of {worker_name} since a task is currently in progress'))


class IdleTimer:
	def __init__(self, timeout):
		self.thread = None
		self.is_started = False
		self.thread = threading.Timer(timeout, kill_worker)

	def start(self):
		if self.is_started:
			self.cancel()
		self.thread.start()
		self.is_started = True

	def cancel(self):
		self.thread.cancel()
		self.s_started = False


IDLE_TIMER = IdleTimer(IDLE_TIMEOUT)


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
		console.print(Info(message=f'Starting inactivity timer for {IDLE_TIMEOUT} seconds ...'))
		IDLE_TIMER.start()


def task_prerun_handler(**kwargs):
	global TASK_IN_PROGRESS, IDLE_TIMER
	TASK_IN_PROGRESS = True
	if IDLE_TIMEOUT != -1:
		IDLE_TIMER.cancel()


def task_postrun_handler(**kwargs):
	global TASK_IN_PROGRESS, IDLE_TIMER
	TASK_IN_PROGRESS = False
	sender_name = kwargs['sender'].name

	if CONFIG.celery.worker_kill_after_task and sender_name.startswith('secator.'):
		worker_name = os.environ['WORKER_NAME']
		console.print(Info(message=f'Shutdown worker {worker_name} since config celery.worker_kill_after_task is set.'))
		IDLE_TIMER.cancel()
		kill_worker()
		return

	if IDLE_TIMEOUT != -1:  # restart timer
		console.print(Info(message=f'Reset inactivity timer to {IDLE_TIMEOUT} seconds'))
		IDLE_TIMER.start()


def setup_handlers():
	signals.celeryd_after_setup.connect(capture_worker_name)
	signals.setup_logging.connect(setup_logging)
	signals.task_prerun.connect(task_prerun_handler)
	signals.task_postrun.connect(task_postrun_handler)
	signals.worker_ready.connect(worker_init_handler)
