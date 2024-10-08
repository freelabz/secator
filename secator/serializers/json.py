import yaml


class JSONSerializer:

	def run(self, line):
		start_index = line.find('{')
		end_index = line.rfind('}')
		if start_index == -1 or end_index == -1:
			return
		try:
			json_obj = line[start_index:end_index+1]
			yield yaml.safe_load(json_obj)
		except yaml.YAMLError:
			return
