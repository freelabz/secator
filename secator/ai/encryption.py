# secator/ai/encryption.py
"""Sensitive data encryption for AI prompts."""
import hashlib
import ipaddress
import re
from typing import Dict, List, Optional

# Key names whose value is a credential in ``key=value`` / ``"key": "value"`` pairs. The key
# may carry a prefix (``db_password``, ``client_secret``, ``AWS_SECRET_ACCESS_KEY``) but must
# END with one of these, so ``token_type`` or ``password_policy`` are not matched. The match
# starts at the key word itself (no prefix scan), which keeps the pattern linear.
_KV_PASSWORD_KEYS = r"(?:password|passwd)"
_KV_SECRET_KEYS = r"(?:secret[_-]?key|secret|token|api[_-]?key|access[_-]?key)"


def _kv_pattern(keys: str) -> re.Pattern:
	"""Build a ``key=value`` / quoted ``"key": "value"`` pattern whose value is group ``v``."""
	return re.compile(
		r"(?<![A-Za-z0-9])" + keys + r"(?:"
		# key=value, unquoted (query strings, env files, CLI flags) or quoted
		r"\s*=\s*(?:\"(?P<v1>[^\"\r\n]+)\"|'(?P<v2>[^'\r\n]+)'|(?P<v3>[^\s\"'&;,<>]+))"
		# "key": "value" (JSON / YAML with a quoted key)
		r"|[\"']\s*:\s*[\"'](?P<v4>[^\"'\r\n]+)[\"']"
		r")",
		re.IGNORECASE,
	)


# PII patterns - order matters (specific before general): each pass skips the placeholders
# of earlier ones. Secrets and URL credentials run before email/ip/host, so a token holding
# dots (JWT) or a ``user:pass@host`` URL is never split by the host or email rule.
# A pattern with named groups ``v``/``v1``... encrypts only that group (the key name or
# header stays readable); otherwise the whole match is encrypted.
PII_PATTERNS = {
	# PEM private key blocks: the base64 body is encrypted, the BEGIN/END lines stay readable.
	"private_key": re.compile(
		r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----(?P<v>[\s\S]{16,16384}?)-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----"
	),
	# Authorization / Proxy-Authorization header values (Bearer / Basic / Token / Digest).
	"auth_header": re.compile(
		r"\bauthorization[\"']?\s*[:=]\s*[\"']?(?:bearer|basic|token|digest)\s+(?P<v>[A-Za-z0-9._~+/=-]{4,})",
		re.IGNORECASE,
	),
	# Password in a URL userinfo: scheme://user:PASS@host. The host is left to the host rule.
	"url_password": re.compile(
		r"\b[A-Za-z][A-Za-z0-9+.-]*://[^\s:/@?#\"'<>]+:(?P<v>[^\s/@?#\"'<>]+)@"
	),
	# Well-known API key / token formats. Fixed prefixes only, so hashes, UUIDs and random
	# base64 blobs are never matched.
	"token": re.compile(
		r"(?<![A-Za-z0-9_-])(?:"
		r"(?:AKIA|ASIA)[0-9A-Z]{16}"                   # AWS access key id
		r"|gh[opsur]_[A-Za-z0-9]{36,}"                  # GitHub tokens
		r"|github_pat_[A-Za-z0-9_]{22,}"                # GitHub fine-grained PAT
		r"|xox[abprs]-[A-Za-z0-9-]{10,}"                # Slack
		r"|AIza[0-9A-Za-z_-]{35}"                       # Google API key
		r"|(?:sk|rk)_live_[0-9A-Za-z]{10,}"             # Stripe live keys
		r"|eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*"  # JWT (incl. unsigned)
		r")(?![A-Za-z0-9_-])"
	),
	"kv_password": _kv_pattern(_KV_PASSWORD_KEYS),
	"kv_secret": _kv_pattern(_KV_SECRET_KEYS),
	# Starts only at the beginning of a run of local-part chars (not at every \b inside it), so a
	# long run with no ``@`` is scanned once instead of once per word boundary. Leading
	# punctuation is trimmed from the match before encryption.
	"email": re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
	# IPv6 candidates (incl. compressed `::` and IPv4-embedded forms); each match is checked
	# with ipaddress before it is encrypted, so times, MACs and the like are left alone.
	# Runs before ipv4 so `::ffff:10.0.0.1` is encrypted whole.
	"ipv6": re.compile(
		r"(?<![0-9A-Za-z:.])(?:[0-9A-Fa-f]{0,4}:){2,7}"
		r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}|[0-9A-Fa-f]{0,4})"
		r"(?![0-9A-Za-z:])"
	),
	"ipv4": re.compile(
		r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
	),
	"host": re.compile(
		r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
	),
}

# Placeholder type minted for each pattern (default: the pattern name). Kept to a few types
# so the model can still tell a password from another secret.
PII_TYPES = {
	"private_key": "secret",
	"auth_header": "secret",
	"url_password": "password",
	"token": "secret",
	"kv_password": "password",
	"kv_secret": "secret",
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


def _is_ipv6(value: str) -> bool:
	"""Return True if ``value`` is a real IPv6 address with at least one hex digit (not a bare ``::``)."""
	if not re.search(r"[0-9A-Fa-f]", value):
		return False
	try:
		ipaddress.IPv6Address(value)
	except ValueError:
		return False
	return True


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


# Placeholder types minted by SensitiveDataEncryptor (built-in PII_TYPES + custom patterns).
_PH_TYPES = r"(?:EMAIL|IPV4|IPV6|HOST|SECRET|PASSWORD|CUSTOM_\d+)"


# A placeholder minted by SensitiveDataEncryptor._hash_value: ``[HOST:1a2b3c4d5e6f]``. Matched
# loosely (any alphanumeric hash) so a model-garbled token like ``[HOST:shhfurirind]`` is caught
# too; the bracket-stripped form is only matched with the exact 12-hex hash to avoid false hits.
_PLACEHOLDER_RE = re.compile(
	r"\[" + _PH_TYPES + r":[A-Za-z0-9]+\]"
	r"|\b" + _PH_TYPES + r":[0-9a-f]{12}\b"
)


# A placeholder exactly as minted by SensitiveDataEncryptor._hash_value. encrypt() never
# matches into these, so a later pattern cannot rewrite part of an earlier placeholder.
_MINTED_PLACEHOLDER_RE = re.compile(r"\[" + _PH_TYPES + r":[0-9a-f]{12}\]")


# Every token shape decrypt() restores, longest first: full placeholder, bracket-stripped form,
# bare hash. Bare forms must not touch a letter or digit, so a hash inside a longer token is
# kept. Unknown tokens are left as-is.
_DECRYPT_TOKEN_RE = re.compile(
	r"\[" + _PH_TYPES + r":[0-9a-f]{12}\]"
	r"|(?<![0-9A-Za-z])" + _PH_TYPES + r":[0-9a-f]{12}(?![0-9A-Za-z])"
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
		value_groups = [g for g in pattern.groupindex if g == "v" or (g[:1] == "v" and g[1:].isdigit())]

		def _repl(match):
			original = match.group()
			if not original:
				return original
			if pii_type == "host" and _is_hash_filename(original):
				return original
			if pii_type == "ipv6" and not _is_ipv6(original):
				return original
			if pii_type == "email":
				value = original.lstrip("._%+-")
				return original[:len(original) - len(value)] + self._hash_value(value, "email")
			ph_type = PII_TYPES.get(pii_type, pii_type)
			if not value_groups:
				return self._hash_value(original, ph_type)
			# Encrypt only the value group; the key name / header around it stays readable.
			group = next((g for g in value_groups if match.group(g)), None)
			if group is None:
				return original
			start, end = match.start(group) - match.start(), match.end(group) - match.start()
			return original[:start] + self._hash_value(original[start:end], ph_type) + original[end:]

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
