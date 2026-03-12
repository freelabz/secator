"""Discord webhook hook for secator.

Sends runner and finding updates to a Discord channel via webhook using embeds.
When a bot_token is configured, each runner gets its own thread: the runner
message is edited in-place and findings are posted inside the thread.
Without a bot_token, everything is posted as top-level messages.

Configuration:
	- addons.discord.enabled: Enable/disable the Discord hook
	- addons.discord.webhook_url: Discord webhook URL
	- addons.discord.bot_token: Discord bot token (enables thread creation)
	- addons.discord.send_runner_updates: Send runner status updates
	- addons.discord.send_findings: Send finding updates
	- addons.discord.finding_types: List of finding types to send (empty = all)
	- addons.discord.min_severity: Minimum severity for vulnerability findings
"""

import time
import requests

from secator.config import CONFIG
from secator.output_types import FINDING_TYPES
from secator.runners import Scan, Task, Workflow
from secator.utils import debug

WEBHOOK_URL = CONFIG.addons.discord.webhook_url
BOT_TOKEN = CONFIG.addons.discord.bot_token
SEND_RUNNER_UPDATES = CONFIG.addons.discord.send_runner_updates
SEND_FINDINGS = CONFIG.addons.discord.send_findings
FINDING_TYPE_FILTER = CONFIG.addons.discord.finding_types
MIN_SEVERITY = CONFIG.addons.discord.min_severity

MAX_RETRIES = 3

FINDING_ICONS = {
	'domain': '\U0001faaa',
	'subdomain': '\U0001f3f0',
	'ip': '\U0001f4bb',
	'port': '\U0001f513',
	'url': '\U0001f517',
	'vulnerability': '\U0001f6a8',
	'exploit': '\u237c',
	'certificate': '\U0001f4dc',
	'tag': '\U0001f3f7\ufe0f',
	'record': '\U0001f3a4',
	'user_account': '\U0001f464',
	'ai': '\U0001f9e0',
}
RUNNER_ICONS = {
	'task': '\U0001f527',
	'workflow': '\u2699\ufe0f',
	'scan': '\U0001f50d',
}

SEVERITY_ORDER = ['info', 'low', 'medium', 'high', 'critical']
SEVERITY_COLORS = {
	'info': 0x3498db,       # blue
	'low': 0x2ecc71,        # green
	'medium': 0xf39c12,     # orange
	'high': 0xe74c3c,       # red
	'critical': 0x8e44ad,   # purple
}
STATUS_COLORS = {
	'RUNNING': 0x3498db,    # blue
	'COMPLETED': 0x2ecc71,  # green
	'SUCCESS': 0x2ecc71,    # green
	'FAILED': 0xe74c3c,     # red
	'SKIPPED': 0x95a5a6,    # gray
}
DEFAULT_COLOR = 0x95a5a6    # gray


def _request_with_retry(method, url, **kwargs):
	"""Make an HTTP request with retry on rate limit (429)."""
	for attempt in range(MAX_RETRIES):
		try:
			response = requests.request(method, url, timeout=10, **kwargs)
			if response.status_code == 429:
				retry_after = response.json().get('retry_after', 1)
				debug(f'rate limited, retrying in {retry_after}s (attempt {attempt + 1}/{MAX_RETRIES})', sub='hooks.discord')  # noqa: E501
				time.sleep(retry_after)
				continue
			response.raise_for_status()
			return response
		except requests.RequestException as e:
			if attempt < MAX_RETRIES - 1:
				debug(f'request failed (attempt {attempt + 1}/{MAX_RETRIES}): {e}', sub='hooks.discord')
				time.sleep(1)
			else:
				debug(f'request failed after {MAX_RETRIES} attempts: {e}', sub='hooks.discord')
	return None


def _create_message(embeds):
	"""Create a new Discord webhook message. Returns (message_id, channel_id)."""
	if not WEBHOOK_URL:
		debug('skipped: no webhook_url configured', sub='hooks.discord')
		return None, None
	response = _request_with_retry('POST', f'{WEBHOOK_URL}?wait=true', json={'embeds': embeds})
	if response:
		data = response.json()
		msg_id = data.get('id')
		channel_id = data.get('channel_id')
		debug(f'message created: {msg_id}', sub='hooks.discord')
		return msg_id, channel_id
	return None, None


def _edit_message(message_id, embeds, thread_id=None):
	"""Edit an existing Discord webhook message."""
	if not WEBHOOK_URL or not message_id:
		return
	url = f'{WEBHOOK_URL}/messages/{message_id}'
	if thread_id:
		url += f'?thread_id={thread_id}'
	response = _request_with_retry('PATCH', url, json={'embeds': embeds})
	if response:
		debug(f'message updated: {message_id}', sub='hooks.discord')


def _create_thread(channel_id, message_id, thread_name):
	"""Create a thread from a message using the bot token. Returns thread_id."""
	if not BOT_TOKEN:
		return None
	url = f'https://discord.com/api/v10/channels/{channel_id}/messages/{message_id}/threads'
	headers = {
		'Authorization': f'Bot {BOT_TOKEN}',
		'Content-Type': 'application/json',
	}
	payload = {'name': thread_name[:100], 'auto_archive_duration': 1440}
	response = _request_with_retry('POST', url, json=payload, headers=headers)
	if response:
		thread_id = response.json().get('id')
		debug(f'thread created: {thread_id}', sub='hooks.discord')
		return thread_id
	return None


def _post_to_thread(thread_id, embeds):
	"""Post a new message inside a thread via webhook."""
	if not WEBHOOK_URL or not thread_id:
		return
	response = _request_with_retry(
		'POST', f'{WEBHOOK_URL}?wait=true&thread_id={thread_id}',
		json={'embeds': embeds}
	)
	if response:
		debug('finding posted to thread', sub='hooks.discord')


def _send_message(embeds):
	"""Post a new top-level Discord webhook message."""
	if not WEBHOOK_URL:
		debug('skipped: no webhook_url configured', sub='hooks.discord')
		return
	response = _request_with_retry('POST', WEBHOOK_URL, json={'embeds': embeds})
	if response:
		debug('message sent', sub='hooks.discord')


def _get_thread_name(runner):
	"""Build a thread name for a runner."""
	runner_type = runner.config.type
	name = runner.config.name
	targets = ', '.join(runner.inputs[:3])
	if len(runner.inputs) > 3:
		targets += f' (+{len(runner.inputs) - 3})'
	return f'{runner_type}: {name} | {targets}'[:100]


def _build_runner_embed(runner):
	"""Build a Discord embed for a runner update."""
	status = runner.status or 'UNKNOWN'
	runner_type = runner.config.type
	name = runner.config.name
	color = STATUS_COLORS.get(status, DEFAULT_COLOR)
	targets = ', '.join(runner.inputs[:5])
	if len(runner.inputs) > 5:
		targets += f' (+{len(runner.inputs) - 5} more)'

	fields = [
		{'name': 'Targets', 'value': targets or 'N/A', 'inline': False},
		{'name': 'Status', 'value': status, 'inline': True},
		{'name': 'Elapsed', 'value': runner.elapsed_human or 'N/A', 'inline': True},
	]
	if runner.progress:
		fields.append({'name': 'Progress', 'value': f'{runner.progress}%', 'inline': True})
	result_count = len(runner.results)
	if result_count > 0:
		fields.append({'name': 'Results', 'value': str(result_count), 'inline': True})

	icon = RUNNER_ICONS.get(runner_type, '')
	return {
		'title': f'{icon} {runner_type.capitalize()}: {name}',
		'color': color,
		'fields': fields,
		'footer': {'text': 'secator'},
		'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
	}


def _build_finding_embed(item):
	"""Build a Discord embed for a finding."""
	finding_type = item._type
	severity = getattr(item, 'severity', None)
	color = SEVERITY_COLORS.get(severity, DEFAULT_COLOR) if severity else DEFAULT_COLOR

	icon = FINDING_ICONS.get(finding_type, '')
	title = f'{icon} {finding_type.capitalize()}'
	item_dict = item.toDict()

	# Pick the most meaningful value for the description
	desc_fields = ['matched_at', 'host', 'url', 'ip', 'domain', 'subdomain', 'name']
	description = ''
	for f in desc_fields:
		val = item_dict.get(f)
		if val:
			description = str(val)
			break

	fields = []
	if severity:
		fields.append({'name': 'Severity', 'value': severity.upper(), 'inline': True})

	# Add key fields (skip internal/empty ones)
	shown = 0
	for k, v in item_dict.items():
		if k.startswith('_') or not v or k in desc_fields:
			continue
		if shown >= 8:
			break
		val_str = str(v)
		if len(val_str) > 200:
			val_str = val_str[:200] + '...'
		fields.append({'name': k, 'value': val_str, 'inline': True})
		shown += 1

	return {
		'title': title,
		'description': description,
		'color': color,
		'fields': fields,
		'footer': {'text': 'secator'},
		'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
	}


def _passes_severity_filter(item):
	"""Check if a finding passes the minimum severity filter."""
	if not MIN_SEVERITY:
		return True
	severity = getattr(item, 'severity', None)
	if not severity:
		return True  # non-vulnerability findings pass through
	try:
		min_idx = SEVERITY_ORDER.index(MIN_SEVERITY.lower())
		item_idx = SEVERITY_ORDER.index(severity.lower())
		return item_idx >= min_idx
	except ValueError:
		return True


def _passes_type_filter(item):
	"""Check if a finding passes the finding type filter."""
	if not FINDING_TYPE_FILTER:
		return True
	return item._type in FINDING_TYPE_FILTER


def update_runner(self):
	"""Send or update runner message on Discord.

	- Top-level runners (workflow/scan without parent) create a message + thread.
	- Child runners (tasks inside a workflow) post their status in the parent's thread.
	"""
	if not SEND_RUNNER_UPDATES:
		return
	embed = _build_runner_embed(self)
	thread_id = self.context.get('_discord_thread_id')

	if self.has_parent and thread_id:
		# Child runner: post/edit own message inside the parent's thread
		own_msg_key = f'_discord_task_msg_{self.unique_name}'
		own_msg_id = self.context.get(own_msg_key)
		if own_msg_id:
			_edit_message(own_msg_id, [embed], thread_id=thread_id)
		else:
			response = _request_with_retry(
				'POST', f'{WEBHOOK_URL}?wait=true&thread_id={thread_id}',
				json={'embeds': [embed]}
			)
			if response:
				own_msg_id = response.json().get('id')
				self.context[own_msg_key] = own_msg_id
				debug(f'task message created in thread: {own_msg_id}', sub='hooks.discord')
	else:
		# Top-level runner: create/edit main message + thread
		msg_key = '_discord_msg_id'
		msg_id = self.context.get(msg_key)
		if msg_id:
			_edit_message(msg_id, [embed])
		else:
			msg_id, channel_id = _create_message([embed])
			if msg_id:
				self.context[msg_key] = msg_id
				if BOT_TOKEN and channel_id:
					thread_name = _get_thread_name(self)
					thread_id = _create_thread(channel_id, msg_id, thread_name)
					if thread_id:
						self.context['_discord_thread_id'] = thread_id


def update_finding(self, item):
	"""Send finding to Discord (in thread if available, otherwise top-level).

	When a thread exists and the finding passes severity filter, also post
	a notification in the main channel linking to the thread.
	"""
	if not SEND_FINDINGS:
		return item
	if type(item) not in FINDING_TYPES:
		return item
	if not _passes_type_filter(item):
		return item
	if not _passes_severity_filter(item):
		return item

	embed = _build_finding_embed(item)
	thread_id = self.context.get('_discord_thread_id')
	if thread_id:
		# Post detailed finding in the thread
		_post_to_thread(thread_id, [embed])
		# Also post a notification in the main channel linking to the thread
		channel_embed = _build_finding_channel_embed(item, thread_id)
		_send_message([channel_embed])
	else:
		_send_message([embed])
	return item


def _build_finding_channel_embed(item, thread_id):
	"""Build a compact embed for the main channel with a link to the thread."""
	finding_type = item._type
	severity = getattr(item, 'severity', None)
	color = SEVERITY_COLORS.get(severity, DEFAULT_COLOR) if severity else DEFAULT_COLOR

	item_dict = item.toDict()
	desc_fields = ['matched_at', 'host', 'url', 'ip', 'domain', 'subdomain', 'name']
	description = ''
	for f in desc_fields:
		val = item_dict.get(f)
		if val:
			description = str(val)
			break

	icon = FINDING_ICONS.get(finding_type, '')
	title = f'{icon} {finding_type.capitalize()}'
	if severity:
		title += f' [{severity.upper()}]'

	fields = []
	if severity:
		fields.append({'name': 'Severity', 'value': severity.upper(), 'inline': True})
	fields.append({'name': 'Details', 'value': f'See <#{thread_id}> for more info', 'inline': False})

	return {
		'title': title,
		'description': description,
		'color': color,
		'fields': fields,
		'footer': {'text': 'secator'},
		'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
	}


HOOKS = {
	Scan: {
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_interval': [update_runner],
		'on_item': [update_finding],
		'on_duplicate': [update_finding],
		'on_end': [update_runner],
	},
	Workflow: {
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_interval': [update_runner],
		'on_item': [update_finding],
		'on_duplicate': [update_finding],
		'on_end': [update_runner],
	},
	Task: {
		'on_init': [update_runner],
		'on_start': [update_runner],
		'on_interval': [update_runner],
		'on_item': [update_finding],
		'on_duplicate': [update_finding],
		'on_end': [update_runner],
	}
}
