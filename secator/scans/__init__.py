from secator.loader import get_configs_by_type
from secator.runners import Scan


class DynamicScan(Scan):
	def __init__(self, config):
		self.config = config

	def __call__(self, targets, **kwargs):
		hooks = kwargs.pop('hooks', {})
		results = kwargs.pop('results', [])
		context = kwargs.pop('context', {})
		super().__init__(
			config=self.config,
			inputs=targets,
			results=results,
			hooks=hooks,
			context=context,
			run_opts=kwargs)
		return self

	def delay(self, targets, **kwargs):
		"""Run scan asynchronously via Celery.

		Args:
			targets: Target(s) for the scan.
			**kwargs: Run options.

		Returns:
			celery.result.AsyncResult: Celery async result.
		"""
		from secator.celery import run_scan

		# Extract special kwargs
		hooks = kwargs.pop('hooks', {})
		results = kwargs.pop('results', [])
		context = kwargs.pop('context', {})

		return run_scan.apply_async(
			kwargs={
				'config': self.config,
				'targets': targets if isinstance(targets, list) else [targets],
				'results': results,
				'run_opts': kwargs,
				'hooks': hooks,
				'context': context
			},
			queue='celery'
		)

	def s(self, targets, **kwargs):
		"""Create a Celery signature for this scan.

		Args:
			targets: Target(s) for the scan.
			**kwargs: Run options.

		Returns:
			celery.canvas.Signature: Celery signature.
		"""
		from secator.celery import run_scan

		hooks = kwargs.pop('hooks', {})
		results = kwargs.pop('results', [])
		context = kwargs.pop('context', {})

		return run_scan.s(
			config=self.config,
			targets=targets if isinstance(targets, list) else [targets],
			results=results,
			run_opts=kwargs,
			hooks=hooks,
			context=context
		)

	def si(self, targets, **kwargs):
		"""Create an immutable Celery signature for this scan.

		Args:
			targets: Target(s) for the scan.
			**kwargs: Run options.

		Returns:
			celery.canvas.Signature: Celery immutable signature.
		"""
		from secator.celery import run_scan

		hooks = kwargs.pop('hooks', {})
		results = kwargs.pop('results', [])
		context = kwargs.pop('context', {})

		return run_scan.si(
			config=self.config,
			targets=targets if isinstance(targets, list) else [targets],
			results=results,
			run_opts=kwargs,
			hooks=hooks,
			context=context
		)


DYNAMIC_SCANS = {}
for scan in get_configs_by_type('scan'):
	instance = DynamicScan(scan)
	DYNAMIC_SCANS[scan.name] = instance

globals().update(DYNAMIC_SCANS)
__all__ = list(DYNAMIC_SCANS)
