import eventlet
eventlet.monkey_patch()
from secator.runners import Workflow, Task, Scan
from secator.template import TemplateLoader
from secator.rich import console
from secator.celery import *
import click
import sys
import json
from time import sleep, time

pool = eventlet.GreenPool(100)

from kombu.serialization import register

def create_runner(runner_type, targets, index, total):
	register('json', json.dumps, json.loads, content_type='application/json', content_encoding='utf-8')
	run_opts = {
		'print_item': True,
		'print_line': True,
		'print_cmd': True
	}
	runner = None
	if runner_type == 'workflow':
		runner = Workflow
		config = TemplateLoader(name='workflows/subdomain_recon')
	elif runner_type == 'task':
		runner = Task
		config = TemplateLoader(input={'name': 'httpx', 'type': 'task'})
	elif runner_type == 'scan':
		runner = Scan
	result = runner.delay(config, targets, run_opts=run_opts)
	while not result.ready():
		# print(f'Running {runner_type} {index}/{total} ..')
		sleep(1)
	print(f'Task {index} / {total} finished running.')
	result.get()

def start_worker():
	from secator.runners import Command
	from threading import Thread
	cmd = f'pyinstrument -r html -o /tmp/test.html --from-path secator worker'
	process = Command.execute(cmd, run=False)
	thread = Thread(target=process.run)
	return thread, process

@click.command()
@click.option('--count', type=int, default=1)
@click.option('--runner', type=str, default='task')
@click.option('--targets', type=str, default='http://testphp.vulnweb.com')
def cli(count, runner, targets):
	"""Secator CLI."""
	try:
		targets = [c.strip() for c in targets.split(',')]
		print(f'Load tester initialized with {len(targets)} targets.')
		print(f'Targets: {targets}')
		thread, process = start_worker()
		print('Starting worker ...')
		thread.start()
		sleep(3)
		print(f'Starting {count} {runner}s ...')
		start_time = time()
		for i in range(count):
			print(f'Starting {runner} {i + 1}/{count} ..')
			pool.spawn(create_runner, runner, targets, i + 1, count)
		pool.waitall()
		elapsed_time = time() - start_time
		print(f'All {runner}s completed in {elapsed_time:.2f}s.')
	except BaseException:
		pass
	finally:
		import signal
		process.send_signal(signal.SIGINT)
		thread.join()

if __name__ == '__main__':
    cli()
