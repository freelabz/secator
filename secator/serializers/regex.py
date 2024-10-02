import re


class RegexSerializer:

	def __init__(self, regex, fields=[], findall=False):
		self.regex = re.compile(regex)
		self.fields = fields
		self.findall = findall

	def run(self, line):
		if self.findall:
			match = self.regex.findall(line)
			yield from match
			return
		output = {}
		match = self.regex.match(line)
		if not match:
			return
		if not self.fields:
			yield match.group(0)
			return
		for field in self.fields:
			output[field] = match.group(field)
		yield output
