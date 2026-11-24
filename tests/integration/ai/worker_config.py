"""Configuration shared by the worker-mode client and workers (same values on both sides)."""
EXTRA_ALLOW = 'shell(sleep,exit,seq)'
AI_QUEUE = 'ai'
# every queue a dispatched child (task, chunk, workflow, chord callback) can land on
POOL_QUEUES = 'small,medium,large,extra_large,celery,results,poll'


def apply_config(config):
	allow = config.addons.ai.permissions['allow']
	if EXTRA_ALLOW not in allow:
		allow.append(EXTRA_ALLOW)
	config.tasks.overrides['ai'] = {**config.tasks.overrides.get('ai', {}), 'profile': AI_QUEUE}
	# 2+ targets are chunked (the eager chord / dispatched-chunks paths)
	config.tasks.overrides['httpx'] = {**config.tasks.overrides.get('httpx', {}), 'input_chunk_size': 1}
