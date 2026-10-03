from secator.runners import Runner


class Celery(Runner):
	def yielder(self):
		if not self.celery_result:
			result = self.build_celery_workflow()
		if self.sync:
			yield from result.apply().get()
		# Live-poll the store (StorePoller) instead of the Celery result backend.
		yield from self._poll_results()

	def error_handler(self, e):
		self.stop_celery_tasks()
