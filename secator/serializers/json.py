import json


class JSONSerializer:

	def __init__(self, strict=False, list=False):
		self.strict = strict
		self.list = list

	def run(self, line):
		if self.list:
			return self._load_list(line)
		else:
			return self._load_single(line)

	def _load_single(self, line):
		start_index = line.find('{')
		end_index = line.rfind('}')
		if start_index == -1 or end_index == -1:
			return
		if start_index != 0 and self.strict:
			return
		try:
			json_obj = line[start_index:end_index+1]
			yield json.loads(json_obj)
		except json.decoder.JSONDecodeError:
			return

	def _load_list(self, line):
		start_index = line.find('[{')
		end_index = line.rfind('}]')
		if start_index == -1 or end_index == -1:
			return
		if start_index != 0 and self.strict:
			return
		try:
			json_obj = line[start_index:end_index+2]
			obj = json.loads(json_obj)
			if isinstance(obj, list):
				for item in obj:
					yield item
			else:
				yield obj
		except json.decoder.JSONDecodeError:
			return
