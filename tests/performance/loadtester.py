import eventlet
eventlet.monkey_patch()
from secator.runners import Workflow
from secator.template import TemplateLoader
from secator.rich import console
from secator.celery import *
import os
import sys
import json
from time import sleep, time

pool = eventlet.GreenPool(100)

from kombu.serialization import register

nworkflows = int(os.environ.get('SECATOR_WORKFLOWS_COUNT', '1'))
targets = [c.strip() for c in os.environ.get('SECATOR_TARGETS', '').split(',') if c]

if not targets:
	console.log('Please specify test targets with SECATOR_TARGETS keys (hosts are comma-separated)', style='bold red')
	sys.exit(1)

if not is_celery_worker_alive():
	console.log('A Celery worker must be running. Start one using "secator worker"', style='bold red')
	sys.exit(1)

console.log(f'Load tester initialized with {len(targets)} targets.')
console.log(f'Targets: {targets}')

def create_runner(index):
	register('json', json.dumps, json.loads, content_type='application/json', content_encoding='utf-8')
	config = TemplateLoader(name='workflows/subdomain_recon')
	run_opts = {
		'sync': False,
		# 'print_start': True,
		'print_item': True,
		# 'print_remote_status': True,
		# 'print_run_summary': True,
		'json': False
	}
	result = Workflow.delay(config, targets, run_opts=run_opts)
	while not result.ready():
		print(f'Running workflow {index + 1}/{nworkflows} ..')
		sleep(2)
	result.get()


if __name__ == '__main__':
	print(f'Starting {nworkflows} workflows ...')
	start_time = time()
	for i in range(nworkflows):
		pool.spawn(create_runner, i)
	pool.waitall()
	elapsed_time = time() - start_time
	print(f'All workflows completed in {elapsed_time:.2f}s.')