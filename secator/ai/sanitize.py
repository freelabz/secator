"""Clean model-written text before it becomes a user-facing prompt."""
import re

# XML-ish control blocks a model sometimes echoes into its own text (a system or
# reminder note it was shown). Dropped with their contents, up to the closing tag
# or the end of the text when it was cut off.
# Only the known injected-note names: a generic `<system_id>` or `<host>` in a real
# question must survive.
_CONTROL_NAMES = r'system[_-](?:warning|reminder|notice|message|note)|[a-z]+_reminder|thinking'
_CONTROL_BLOCK = re.compile(rf'<({_CONTROL_NAMES})\b[^>]*>[\s\S]*?(?:</\1\s*>|$)', re.IGNORECASE)
_CONTROL_TAG = re.compile(rf'</?(?:{_CONTROL_NAMES})\b[^>]*>', re.IGNORECASE)
# A sentence that is wholly a template placeholder copied verbatim instead of filled
# in ("Summary sentence goes here.", "[summary]"). Questions ("Which key goes here?")
# and sentences that merely contain the words are kept.
_PLACEHOLDER_SENTENCE = re.compile(
	r'^\s*(?:[\w ]{0,40}\bgoes here[.!]?|lorem ipsum dolor\b.*'
	r'|[\[{<]\s*(?:summary|reason|question|text|sentence|answer)\s*[\]}>][.!]?)\s*$',
	re.IGNORECASE)
_SENTENCE_SPLIT = re.compile(r'(?<=[.!?])\s+')


def clean_model_text(text):
	"""Strip leaked control blocks and copied template placeholders from model text.

	Used on the text of an end-of-turn prompt (the `stop` reason, or a content-only
	reply) so a question shown to the user never carries e.g. a ``<system_warning>``
	block or a "Summary sentence goes here." line. Returns '' when nothing real is
	left, so callers can fall back to a default.
	"""
	if not isinstance(text, str) or not text:
		return ''
	stripped = _CONTROL_TAG.sub(' ', _CONTROL_BLOCK.sub(' ', text))
	lines, dropped = [], False
	for line in stripped.splitlines():
		body = line.strip()
		if not body:
			lines.append('')
			continue
		# Keep the line's indentation (code blocks); only whole sentences are dropped.
		indent = line[:len(line) - len(line.lstrip())]
		sentences = [s for s in _SENTENCE_SPLIT.split(body) if s]
		kept = [s for s in sentences if not _PLACEHOLDER_SENTENCE.search(s)]
		dropped = dropped or len(kept) != len(sentences)
		if kept:
			lines.append((indent + ' '.join(kept)).rstrip())
	if stripped == text and not dropped:
		return text.strip()  # common case: keep the model's formatting untouched
	return re.sub(r'\n{3,}', '\n\n', '\n'.join(lines)).strip()
