import threading

from secator.output_types import Error


class Thread(threading.Thread):
    """A thread that returns errors in their join() method as secator.output_types.Error."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.error = None

    def run(self):
        try:
            if hasattr(self, '_target'):
                self._target(*self._args, **self._kwargs)
        except Exception as e:
            self.error = Error.from_exception(e)

    def join(self, *args, **kwargs):
        super().join(*args, **kwargs)
        if self.error:
            return self.error
        return None
