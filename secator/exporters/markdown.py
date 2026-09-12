from secator.exporters._base import Exporter
from secator.output_types import Info
from secator.rich import console


class MarkdownExporter(Exporter):
	def send(self):
		results = self.report.data['results']
		ai_items = results.get('ai', [])
		if not ai_items:
			return

		# report.data['results']['ai'] holds serialized dicts, not Ai objects, so
		# read `content` defensively (handle both dict and OutputType forms).
		def _content(item):
			if isinstance(item, dict):
				return item.get('content')
			return getattr(item, 'content', None)

		sections = [c for item in ai_items if (c := _content(item))]
		if not sections:
			return

		md_path = f'{self.report.output_folder}/report_ai.md'
		with open(md_path, 'w') as f:
			f.write('\n\n---\n\n'.join(sections))

		if getattr(self.report.runner, 'print_reports_message', True):
			console.print(Info(f'Saved Markdown report to {md_path}'))
