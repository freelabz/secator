"""Celery worker module of the worker-mode ai scenarios (``celery worker -I <this module>``).

Patches the scripted model in at the litellm boundary of this worker (requests recorded to
``$AI_E2E_RECORD``), blocks non-loopback network, and applies the test configuration the
in-process scenarios use (shell allow-list, ai queue, chunk size).
"""
import os
import sys

os.environ.setdefault('LITELLM_LOCAL_MODEL_COST_MAP', 'True')

from secator.celery import app  # noqa: E402,F401  (the app this worker serves)
from secator.config import CONFIG  # noqa: E402

from tests.integration.ai import worker_scenarios  # noqa: E402
from tests.integration.ai.scripted import NetworkGuard, ScriptedModel  # noqa: E402
from tests.integration.ai.worker_config import apply_config  # noqa: E402

apply_config(CONFIG)
MODEL = ScriptedModel(record_path=os.environ['AI_E2E_RECORD'], scenario_factory=worker_scenarios.build)
for _patcher in MODEL.patchers():
	_patcher.start()
NetworkGuard(on_block=lambda addr: print(f'AI-E2E-NETWORK-BLOCKED {addr}', file=sys.stderr, flush=True)).start()


from celery.signals import worker_ready  # noqa: E402


@worker_ready.connect
def _announce_ready(**kwargs):
	print('AI-E2E-WORKER-READY', file=sys.stderr, flush=True)
