import re


class RegexSerializer:

	def __init__(self, regex, fields=[]):
		self.regex = re.compile(regex)
		self.fields = fields

	def run(self, line):
		match = self.regex.match(line)
		output = {}
		if not match:
			return
		if not self.fields:
			yield match.group(0)
			return
		for field in self.fields:
			output[field] = match.group(field)
		yield output
