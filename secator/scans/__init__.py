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


DYNAMIC_SCANS = {}
for scan in get_configs_by_type('scan'):
	instance = DynamicScan(scan)
	DYNAMIC_SCANS[scan.name] = instance

globals().update(DYNAMIC_SCANS)
__all__ = list(DYNAMIC_SCANS)
