from secator.celery_utils import CeleryData
from secator.runners import Runner


class Celery(Runner):
	def yielder(self):
		if not self.celery_result:
			result = self.build_celery_workflow()
		if self.sync:
			yield from result.apply().get()
		yield from CeleryData.iter_results(
			self.celery_result,
			ids_map=self.celery_ids_map,
			print_remote_info=False
		)

	def error_handler(self, e):
		self.stop_celery_tasks()
