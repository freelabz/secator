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

    def encrypt(self, text: str) -> str:
        """Encrypt all sensitive data in text."""
        if not text:
            return text

        result = text

        # Custom patterns first
        for i, pattern in enumerate(self.custom_patterns):
            for match in pattern.finditer(result):
                original = match.group()
                placeholder = self._hash_value(original, f"custom_{i}")
                result = result.replace(original, placeholder)

        # Built-in patterns
        for pii_type, pattern in PII_PATTERNS.items():
            for match in pattern.finditer(result):
                original = match.group()
                placeholder = self._hash_value(original, pii_type)
                result = result.replace(original, placeholder)

        return result

    def decrypt(self, text: str) -> str:
        """Restore original sensitive values from placeholders."""
        result = text

        # Full placeholders [TYPE:hash]
        for placeholder, original in self.pii_map.items():
            result = result.replace(placeholder, original)

        # Without brackets TYPE:hash
        for placeholder, original in self.pii_map.items():
            no_brackets = placeholder[1:-1]
            result = result.replace(no_brackets, original)

        # Bare hashes
        for hash_value, original in self.hash_map.items():
            result = result.replace(hash_value, original)

        return result
