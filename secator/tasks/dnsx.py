from secator.decorators import task
from secator.definitions import (OPT_PIPE_INPUT, RATE_LIMIT, RETRIES, THREADS)
from secator.output_types import Record
from secator.tasks._categories import ReconDns
import json


@task()
class dnsx(ReconDns):
	"""dnsx is a fast and multi-purpose DNS toolkit designed for running various retryabledns library."""
	cmd = 'dnsx -resp -a -aaaa -cname -mx -ns -txt -srv -ptr -soa -axfr -caa'
	json_flag = '-json'
	input_flag = OPT_PIPE_INPUT
	file_flag = OPT_PIPE_INPUT
	output_types = [Record]
	opt_key_map = {
		RATE_LIMIT: 'rate-limit',
		RETRIES: 'retry',
		THREADS: 'threads',
	}
	opts = {

	}

	install_cmd = 'go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest'

	def item_loader(self, line):
		items = []
		try:
			item = json.loads(line)

			# TODO: temp fix for test fixture with item_loader
			if 'host' in item and 'name' in item and 'type' in item:
				items.append(item)
				return items

			host = item['host']
			record_types = ['a', 'aaaa', 'cname', 'mx', 'ns', 'txt', 'srv', 'ptr', 'soa', 'axfr', 'caa']
			for _type in record_types:
				values = item.get(_type, [])
				for value in values:
					items.append({
						'host': host,
						'name': value,
						'type': _type.upper(),
					})
		except json.decoder.JSONDecodeError:
			pass

		return items
