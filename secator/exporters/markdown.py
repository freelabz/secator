from secator.exporters._base import Exporter
from secator.output_types import Info
from secator.rich import console


class MarkdownExporter(Exporter):
	def send(self):
		results = self.report.data['results']
		ai_items = results.get('ai', [])
		if not ai_items:
			return

		sections = [item.content for item in ai_items if item.content]
		if not sections:
			return

		md_path = f'{self.report.output_folder}/report_ai.md'
		with open(md_path, 'w') as f:
			f.write('\n\n---\n\n'.join(sections))

		console.print(Info(f'Saved Markdown report to {md_path}'))
