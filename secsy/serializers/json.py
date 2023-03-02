import yaml


class JSONSerializer:

	def run(self, line):
		if not (line.startswith('{') and line.endswith('}')):
			return None
		try:
			return yaml.safe_load(line)
		except yaml.YAMLError:
			return None