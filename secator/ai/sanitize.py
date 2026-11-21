"""Clean model-written text before it becomes a user-facing prompt."""
import re

# XML-ish control blocks a model sometimes echoes into its own text (a system or
# reminder note it was shown). Dropped with their contents, up to the closing tag
# or the end of the text when it was cut off.
_CONTROL_NAMES = r'system(?:[_-][\w-]*)?|[\w-]*_(?:warning|reminder)|reminder|thinking'
_CONTROL_BLOCK = re.compile(rf'<({_CONTROL_NAMES})\b[^>]*>[\s\S]*?(?:</\1\s*>|$)', re.IGNORECASE)
_CONTROL_TAG = re.compile(rf'</?(?:{_CONTROL_NAMES})\b[^>]*>', re.IGNORECASE)
# A sentence that is a template placeholder copied verbatim instead of filled in.
_PLACEHOLDER_SENTENCE = re.compile(
	r'\b(goes here|lorem ipsum|insert [\w ]+ here|fill (?:this|me) in)\b'
	r'|^\s*[\[{<]\s*[\w ]+\s*[\]}>]\s*[.!?]?\s*$',
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
	if stripped == text and not _PLACEHOLDER_SENTENCE.search(text):
		return text.strip()  # common case: keep the model's formatting untouched
	lines = []
	for line in stripped.splitlines():
		kept = [s for s in _SENTENCE_SPLIT.split(line.strip()) if s and not _PLACEHOLDER_SENTENCE.search(s)]
		if kept:
			lines.append(re.sub(r'[ \t]+', ' ', ' '.join(kept)))
	return '\n'.join(lines).strip()
