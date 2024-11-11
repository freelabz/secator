import json


class JSONSerializer:

	def __init__(self, strict=False):
		self.strict = strict

	def run(self, line):
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
