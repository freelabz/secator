# secator/ai/encryption.py
"""Sensitive data encryption for AI prompts."""
import hashlib
import re
from typing import Dict, List, Optional

# PII patterns - order matters (specific before general)
PII_PATTERNS = {
	"email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
	"ipv4": re.compile(
		r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
	),
	"host": re.compile(
		r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
	),
}

# File extensions that are never TLDs — prevents hex hash filenames (e.g. sha1.txt) from
# being treated as hostnames by the host pattern.
_FAKE_HOST_EXTENSIONS = frozenset({
	'txt', 'json', 'xml', 'html', 'htm', 'log', 'csv', 'md',
	'yaml', 'yml', 'toml', 'ini', 'cfg', 'conf',
	'py', 'js', 'ts', 'sh', 'bash', 'rb', 'php', 'go', 'rs', 'java', 'c', 'h', 'cpp',
	'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico', 'pdf',
	'zip', 'tar', 'gz', 'bz2', 'xz', 'mp3', 'mp4',
})


def _is_hash_filename(hostname: str) -> bool:
	"""Return True if the matched hostname looks like a hash filename rather than a real host.

	Prevents false-positive encryption of paths like:
	  fefdc75b8092569ffdaaf5c91522f10d063a93d2.txt   (SHA-1 hash from httpx)
	  d41d8cd98f00b204e9800998ecf8427e.json          (MD5 hash)
	"""
	dot_idx = hostname.rfind('.')
	if dot_idx < 0:
		return False
	label = hostname[:dot_idx].lower()
	ext = hostname[dot_idx + 1:].lower()
	# Only skip if TLD is a known file extension and the label is a pure hex string
	# of a length typical for cryptographic hashes (MD5=32, SHA1=40, SHA256=64, etc.)
	if ext in _FAKE_HOST_EXTENSIONS and re.fullmatch(r'[0-9a-f]{8,}', label):
		return True
	return False


# A placeholder minted by SensitiveDataEncryptor._hash_value: ``[HOST:1a2b3c4d5e6f]``. Matched
# loosely (any alphanumeric hash) so a model-garbled token like ``[HOST:shhfurirind]`` is caught
# too; the bracket-stripped form is only matched with the exact 12-hex hash to avoid false hits.
_PLACEHOLDER_RE = re.compile(
	r"\[(?:EMAIL|IPV4|HOST|CUSTOM_\d+):[A-Za-z0-9]+\]"
	r"|\b(?:EMAIL|IPV4|HOST|CUSTOM_\d+):[0-9a-f]{12}\b"
)


# A placeholder exactly as minted by SensitiveDataEncryptor._hash_value. encrypt() never
# matches into these, so a later pattern cannot rewrite part of an earlier placeholder.
_MINTED_PLACEHOLDER_RE = re.compile(r"\[(?:EMAIL|IPV4|HOST|CUSTOM_\d+):[0-9a-f]{12}\]")


# Every token shape decrypt() restores, longest first: full placeholder, bracket-stripped form,
# bare hash. Bare forms must not touch a letter or digit, so a hash inside a longer token is
# kept. Unknown tokens are left as-is.
_DECRYPT_TOKEN_RE = re.compile(
	r"\[(?:EMAIL|IPV4|HOST|CUSTOM_\d+):[0-9a-f]{12}\]"
	r"|(?<![0-9A-Za-z])(?:EMAIL|IPV4|HOST|CUSTOM_\d+):[0-9a-f]{12}(?![0-9A-Za-z])"
	r"|(?<![0-9A-Za-z])[0-9a-f]{12}(?![0-9A-Za-z])"
)


def find_placeholders(value) -> list:
	"""Return every sensitive-data placeholder left in ``value`` (str / dict / list, recursive).

	Run on tool-call arguments AFTER decryption: anything still matching is a placeholder the
	session's map can't resolve (unknown, garbled, or from a map that was not restored). Such a
	call must never run as-is — it would hit e.g. ``http://[HOST:...]`` literally.
	"""
	found = []
	if isinstance(value, str):
		found.extend(m.group() for m in _PLACEHOLDER_RE.finditer(value))
	elif isinstance(value, dict):
		for v in value.values():
			found.extend(find_placeholders(v))
	elif isinstance(value, (list, tuple)):
		for v in value:
			found.extend(find_placeholders(v))
	return list(dict.fromkeys(found))


def maybe_encrypt(text, encryptor):
	"""Encrypt text if encryptor is available, otherwise return as-is."""
	return encryptor.encrypt(text) if encryptor else text


class SensitiveDataEncryptor:
	"""Encrypt sensitive data using SHA-256 hashing with salt.

	This class provides reversible encryption of sensitive data (PII) in text
	by replacing matches with hashed placeholders. The original values can be
	restored using the decrypt method.

	Attributes:
		salt: Salt string used for hashing to ensure unique placeholders.
		pii_map: Mapping of placeholders to original values.
		hash_map: Mapping of bare hashes to original values.
		custom_patterns: List of compiled regex patterns for custom PII types.
	"""

	def __init__(
		self,
		salt: str = "secator_pii_salt",
		custom_patterns: Optional[List[str]] = None
	) -> None:
		"""Initialize the encryptor with optional salt and custom patterns.

		Args:
			salt: Salt string used for hashing. Defaults to "secator_pii_salt".
			custom_patterns: Optional list of regex patterns or literal strings
				to match as custom PII types. Lines starting with '#' are ignored.
		"""
		self.salt = salt
		self.pii_map: Dict[str, str] = {}  # placeholder -> original
		self.hash_map: Dict[str, str] = {}  # bare hash -> original
		self.custom_patterns: List[re.Pattern] = []

		if custom_patterns:
			for pattern in custom_patterns:
				pattern = pattern.strip()
				if not pattern or pattern.startswith("#"):
					continue
				try:
					self.custom_patterns.append(re.compile(pattern))
				except re.error:
					self.custom_patterns.append(re.compile(re.escape(pattern)))

	def _hash_value(self, value: str, pii_type: str) -> str:
		"""Hash a sensitive value and return a placeholder."""
		hash_input = f"{self.salt}:{pii_type}:{value}"
		hash_value = hashlib.sha256(hash_input.encode()).hexdigest()[:12]
		placeholder = f"[{pii_type.upper()}:{hash_value}]"
		self.pii_map[placeholder] = value
		self.hash_map[hash_value] = value
		return placeholder

	def _sub_outside_placeholders(self, text: str, pattern: re.Pattern, pii_type: str) -> str:
		"""Replace each whole match of ``pattern`` in ``text`` with its placeholder.

		Replacement is by match span (never a substring replace), so a value is only ever
		replaced where it matched in full: ``10.10.0.1`` never rewrites part of ``10.10.0.12``.
		Placeholders already in ``text`` are left untouched and never matched into.
		"""
		def _repl(match):
			original = match.group()
			if not original:
				return original
			if pii_type == "host" and _is_hash_filename(original):
				return original
			return self._hash_value(original, pii_type)

		def _sub_range(start, end):
			# Match on the full string bounded by pos/endpos (not a slice), so anchors and
			# lookbehinds still see the real surrounding text.
			last = start
			for match in pattern.finditer(text, start, end):
				out.append(text[last:match.start()])
				out.append(_repl(match))
				last = match.end()
			out.append(text[last:end])

		out = []
		last = 0
		for ph in _MINTED_PLACEHOLDER_RE.finditer(text):
			_sub_range(last, ph.start())
			out.append(ph.group())
			last = ph.end()
		_sub_range(last, len(text))
		return "".join(out)

	def encrypt(self, text: str) -> str:
		"""Encrypt all sensitive data in text."""
		if not text:
			return text

		result = text

		# Custom patterns first, then built-ins; later passes skip earlier placeholders.
		for i, pattern in enumerate(self.custom_patterns):
			result = self._sub_outside_placeholders(result, pattern, f"custom_{i}")
		for pii_type, pattern in PII_PATTERNS.items():
			result = self._sub_outside_placeholders(result, pattern, pii_type)

		return result

	def decrypt(self, text: str) -> str:
		"""Restore original sensitive values from placeholders.

		Handles full placeholders ``[TYPE:hash]``, their bracket-stripped form ``TYPE:hash`` and
		bare hashes. Done in a single pass (restored values are never re-scanned), longest token
		first, and bare forms only when not touching a letter or digit, so a hash inside a longer
		token is kept.
		"""
		if not text:
			return text

		def _restore(match):
			token = match.group()
			if token in self.pii_map:
				return self.pii_map[token]
			if f"[{token}]" in self.pii_map:
				return self.pii_map[f"[{token}]"]
			return self.hash_map.get(token.strip("[]").rsplit(":", 1)[-1], token)

		return _DECRYPT_TOKEN_RE.sub(_restore, text)
