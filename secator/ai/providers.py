# secator/ai/providers.py
"""Named AI provider presets for the secator AI addon.

Secator reaches models through litellm, which already knows how to talk to
most vendors from a model string alone (``claude-sonnet-4-6``, ``gpt-4o``, ...).
A *named provider preset* adds the pieces litellm cannot infer for a gateway:

* the inference base URL (``https://api.orcarouter.ai/v1``);
* the environment variable that may hold the user's key;
* the provider's live model catalog and the capability filtering applied to it;
* the wire mapping that keeps the catalog's ``vendor/model`` namespace intact
while still selecting the OpenAI-compatible adapter.

OrcaRouter is the first preset. It is a first-class entry
(``addons.ai.provider: orcarouter``) rather than a free-form ``api_base``: the
preset owns its catalog, its verified fallback seed and its capability rules,
so the model selector never has to guess which ``vendor/model`` strings the
user's workspace can actually call.

Nothing in this module logs, prints or stores the API key. The key is only ever
sent as a Bearer header to the inference origin and is excluded from every
error message.
"""
import hashlib
import ipaddress
import json
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlsplit

from secator.requests import get_session


DEFAULT_TIMEOUT = 8.0
MAX_CATALOG_BYTES = 2_000_000
MAX_CATALOG_ITEMS = 500
CATALOG_CACHE_TTL = 300.0

# Endpoint types the text chat / agent entry can speak. A model is only offered
# in the chat selector when it advertises at least one of these.
TEXT_ENDPOINT_TYPES = frozenset({'openai', 'anthropic', 'gemini', 'openai-response'})
NON_TEXT_ENDPOINT_TYPES = frozenset({'image-generation', 'openai-video', 'jina-rerank'})

# Capability -> endpoint types that prove it. Used by every AI entry point so a
# model is never offered where its wire protocol cannot be served.
CAPABILITY_ENDPOINT_TYPES = {
	'chat': TEXT_ENDPOINT_TYPES,
	'embedding': frozenset({'embeddings'}),
	'image': frozenset({'image-generation'}),
	'video': frozenset({'openai-video'}),
	'rerank': frozenset({'jina-rerank'}),
}


class ProviderError(Exception):
	"""Base error for named AI providers."""


class ProviderConfigError(ProviderError):
	"""The provider is unknown or its configuration is unusable."""


class CatalogError(ProviderError):
	"""The live model catalog could not be loaded.

	``kind`` classifies the failure for callers that render a user-facing hint:
	``auth``, ``rate_limit``, ``network``, ``timeout``, ``invalid_response``,
	``empty`` or ``http``. Messages never contain the API key.
	"""

	def __init__(self, message: str, status: Optional[int] = None, kind: str = 'http'):
		super().__init__(message)
		self.status = status
		self.kind = kind


@dataclass(frozen=True)
class ProviderSpec:
	"""Static description of a named provider preset."""

	id: str
	label: str
	default_api_base: str
	env_key: str
	key_prefix: str
	console_url: str
	docs_url: str
	wire_prefix: str = 'openai/'

	def __str__(self):  # pragma: no cover - cosmetic
		return self.label


ORCAROUTER = ProviderSpec(
	id='orcarouter',
	label='OrcaRouter',
	default_api_base='https://api.orcarouter.ai/v1',
	env_key='ORCAROUTER_API_KEY',
	key_prefix='sk-orca-',
	console_url='https://www.orcarouter.ai/console',
	docs_url='https://docs.orcarouter.ai',
)

PROVIDERS: Dict[str, ProviderSpec] = {ORCAROUTER.id: ORCAROUTER}


@dataclass(frozen=True)
class CatalogModel:
	"""One model record from a provider catalog (or its verified seed)."""

	id: str
	context_length: int = 0
	input_modalities: Tuple[str, ...] = ('text',)
	output_modalities: Tuple[str, ...] = ('text',)
	endpoint_types: Tuple[str, ...] = ('openai',)
	reasoning: bool = False
	reasoning_efforts: Tuple[str, ...] = ()
	source: str = 'live'

	@property
	def supports_text(self) -> bool:
		return bool(set(self.endpoint_types) & TEXT_ENDPOINT_TYPES)

	@property
	def supports_image_input(self) -> bool:
		return 'image' in self.input_modalities


@dataclass(frozen=True)
class CatalogResult:
	"""Outcome of a catalog lookup.

	``source`` is ``live`` when the provider answered, ``last_known_good`` when a
	previous live answer is reused after a failure, and ``fallback`` when only
	the small verified seed is available. ``degraded`` is True for the latter two
	so the UI can say so explicitly instead of silently showing a stale list.
	"""

	models: Tuple[CatalogModel, ...]
	source: str
	degraded: bool
	error: Optional[str] = None


# Verified cold-start seed. Used only when the live catalog is unavailable; it
# is deliberately tiny and every entry mirrors the metadata the catalog served.
# Verified against GET https://api.orcarouter.ai/v1/models?capability=chat on
# 2026-10-24 (the ids and context windows below are the live values).
VERIFIED_FALLBACK_MODELS: Tuple[CatalogModel, ...] = (
	CatalogModel(
		id='deepseek/deepseek-v4-pro',
		context_length=1_048_576,
		input_modalities=('text',),
		endpoint_types=('openai', 'openai-response'),
		source='fallback',
	),
	CatalogModel(
		id='orcarouter/fusion',
		context_length=1_000_000,
		input_modalities=('text',),
		endpoint_types=('openai', 'openai-response', 'anthropic', 'gemini'),
		source='fallback',
	),
	CatalogModel(
		id='orca/orcacyber-ultra-1.0',
		context_length=1_048_576,
		input_modalities=('text',),
		endpoint_types=('openai',),
		source='fallback',
	),
	CatalogModel(
		id='deepseek/deepseek-v4-flash',
		context_length=1_048_576,
		input_modalities=('text',),
		endpoint_types=('openai', 'openai-response'),
		source='fallback',
	),
)

# model id -> context window learned from a live catalog. Consulted by
# secator.ai.history.get_context_window so OrcaRouter models report the window
# their own catalog advertised instead of the generic config fallback.
_KNOWN_CONTEXT_WINDOWS: Dict[str, int] = {}
# Every catalog id seen in a live response, in the verified seed, or in a cached
# catalog. Used to tell a catalog id (``deepseek/deepseek-v4-pro``) apart from a
# model string already mapped for litellm (``openai/deepseek/deepseek-v4-pro``).
_KNOWN_MODEL_IDS: Set[str] = set()
# cache key -> (monotonic timestamp, models)
_CATALOG_CACHE: Dict[str, Tuple[float, Tuple[CatalogModel, ...]]] = {}
# api base -> last successful live catalog
_LAST_KNOWN_GOOD: Dict[str, Tuple[CatalogModel, ...]] = {}


# ---------------------------------------------------------------------------
# Provider lookup and configuration
# ---------------------------------------------------------------------------

def get_provider(provider_id: Optional[str]) -> Optional[ProviderSpec]:
	"""Return the preset for ``provider_id`` (case-insensitive) or None."""
	if not provider_id:
		return None
	return PROVIDERS.get(str(provider_id).strip().lower())


def require_provider(provider_id: Optional[str]) -> ProviderSpec:
	spec = get_provider(provider_id)
	if spec is None:
		known = ', '.join(sorted(PROVIDERS))
		raise ProviderConfigError(
			f"Unknown AI provider '{provider_id}'. Supported named providers: {known}."
		)
	return spec


def _is_loopback(hostname: str) -> bool:
	if hostname in ('localhost', '127.0.0.1', '::1'):
		return True
	try:
		return ipaddress.ip_address(hostname).is_loopback
	except ValueError:
		return False


def validate_api_base(url: str) -> str:
	"""Validate an inference base URL and return it without a trailing slash.

	HTTPS is required for remote origins; plain HTTP is accepted only for
	loopback development, matching the provider's own callback policy. Credentials,
	query strings and fragments are rejected so a key can never ride in the URL.
	"""
	parts = urlsplit(url or '')
	if parts.scheme not in ('http', 'https') or not parts.hostname:
		raise ProviderConfigError(
			f"Invalid AI API base URL '{url}'. Use an absolute http(s) URL."
		)
	if parts.scheme == 'http' and not _is_loopback(parts.hostname):
		raise ProviderConfigError(
			'AI API base URL must use HTTPS (HTTP is only allowed for loopback development).'
		)
	if parts.username or parts.password:
		raise ProviderConfigError('AI API base URL must not embed credentials.')
	if parts.query or parts.fragment:
		raise ProviderConfigError('AI API base URL must not contain a query string or fragment.')
	return url.rstrip('/')


def resolve_api_base(provider_id: str, configured_base: str = '', env: Optional[Dict[str, str]] = None) -> str:
	"""Resolve the inference base URL for a named provider.

	Precedence: explicit ``addons.ai.api_base`` -> ``ORCA_API_BASE_URL`` ->
	shared self-hosted ``ORCA_BASE_URL`` (``/v1`` appended when absent) ->
	the provider default. Explicit values always win over the shared fallback.
	"""
	spec = require_provider(provider_id)
	environ = os.environ if env is None else env

	base = (configured_base or '').strip()
	if not base:
		base = (environ.get('ORCA_API_BASE_URL') or '').strip()
	if not base:
		shared = (environ.get('ORCA_BASE_URL') or '').strip()
		if shared:
			shared = shared.rstrip('/')
			base = shared if shared.endswith('/v1') else shared + '/v1'
	if not base:
		base = spec.default_api_base
	return validate_api_base(base)


def resolve_api_key(provider_id: str, configured_key: str = '',
					env: Optional[Dict[str, str]] = None) -> str:
	"""Resolve the API key from the project config or the provider's env var.

	The configured value (``addons.ai.api_key`` / ``SECATOR_ADDONS_AI_API_KEY``)
	wins; the provider env var is the fallback. Never raises with the key in
	the message and never logs it.
	"""
	spec = require_provider(provider_id)
	environ = os.environ if env is None else env
	return (configured_key or '').strip() or (environ.get(spec.env_key) or '').strip()


def mask_api_key(key: Optional[str]) -> str:
	"""Mask a secret for display: first 8 + last 4 characters, like the CLI."""
	if not key:
		return ''
	if len(key) <= 12:
		return '…'
	return f'{key[:8]}…{key[-4:]}'


def key_prefix_matches(provider_id: str, key: str) -> bool:
	"""Lightweight format hint only — never a validity check."""
	spec = get_provider(provider_id)
	return bool(spec and key and key.strip().startswith(spec.key_prefix))


def to_litellm_model(provider_id: Optional[str], model_id: str) -> str:
	"""Map a catalog model id to the litellm model string.

	The OpenAI-compatible adapter is selected with the outer ``openai/`` prefix
	while the catalog's own ``vendor/model`` namespace is preserved::

		orcarouter + deepseek/deepseek-v4-pro -> openai/deepseek/deepseek-v4-pro

	litellm splits on the first ``/`` and forwards ``deepseek/deepseek-v4-pro`` as the
	wire model, which is exactly what the gateway expects.

	Mapping is idempotent for known catalog ids: an already-mapped
	``openai/deepseek/deepseek-v4-pro`` is returned unchanged, while the catalog
	id ``deepseek/deepseek-v4-pro`` is prefixed once. Catalog ids are recognised from live
	discovery, cached catalogs and the verified seed.
	"""
	if not provider_id:
		return model_id
	spec = require_provider(provider_id)
	model_id = (model_id or '').strip()
	if not model_id:
		return model_id
	if model_id.startswith(spec.wire_prefix):
		if model_id[len(spec.wire_prefix):] in _KNOWN_MODEL_IDS:
			return model_id
	return f'{spec.wire_prefix}{model_id}'


# ---------------------------------------------------------------------------
# Catalog parsing and capability filtering
# ---------------------------------------------------------------------------

def _str_tuple(value: Any) -> Tuple[str, ...]:
	if value is None:
		return ()
	if isinstance(value, str):
		value = [value]
	if not isinstance(value, (list, tuple)):
		return ()
	out: List[str] = []
	for item in value:
		if isinstance(item, str) and item.strip():
			s = item.strip().lower()
			if s not in out:
				out.append(s)
	return tuple(out)


def _int_or_zero(value: Any) -> int:
	try:
		n = int(value)
	except (TypeError, ValueError):
		return 0
	return n if n > 0 else 0


def parse_model_record(record: Any) -> Optional[CatalogModel]:
	"""Parse one ``/v1/models`` record; return None for unusable entries.

	Accepts the OpenAI-compatible shape (``data[]``) enriched with
	``architecture.input_modalities`` and ``supported_endpoint_types``. Records
	without a usable id or without any endpoint declaration are dropped; a model
	that does not prove it can serve text is not offered to the chat selector.
	"""
	if not isinstance(record, dict):
		return None
	model_id = record.get('id')
	if not isinstance(model_id, str):
		return None
	model_id = model_id.strip()
	if not model_id or len(model_id) > 200 or any(ch.isspace() for ch in model_id):
		return None

	architecture = record.get('architecture')
	if not isinstance(architecture, dict):
		architecture = {}
	endpoints = _str_tuple(record.get('supported_endpoint_types'))
	if not endpoints:
		endpoints = _str_tuple(record.get('supported_endpoints'))
	input_modalities = _str_tuple(architecture.get('input_modalities'))
	output_modalities = _str_tuple(architecture.get('output_modalities'))
	context_length = _int_or_zero(
		record.get('context_length')
		or record.get('context_window')
		or record.get('max_input_tokens')
	)
	reasoning = bool(record.get('reasoning') or record.get('supports_reasoning'))
	efforts = _str_tuple(
		record.get('reasoning_efforts')
		or record.get('supported_reasoning_efforts')
		or (architecture.get('reasoning_efforts') if isinstance(architecture, dict) else None)
	)
	return CatalogModel(
		id=model_id,
		context_length=context_length,
		input_modalities=input_modalities or ('text',),
		output_modalities=output_modalities or ('text',),
		endpoint_types=endpoints,
		reasoning=reasoning,
		reasoning_efforts=efforts,
		source='live',
	)


def filter_models(models: Iterable[CatalogModel], capability: str = 'chat',
				  input_modalities: Sequence[str] = ()) -> Tuple[CatalogModel, ...]:
	"""Filter catalog entries for one AI entry point.

	* ``capability`` selects the required endpoint types (chat, embedding, image,
	  video, rerank). A model only passes when it advertises one of them.
	* ``input_modalities`` is fail-closed: when the entry point uploads a
	  modality, a model must *explicitly* declare it. Undeclared capabilities are
	  never inferred from the model name.
	"""
	required = CAPABILITY_ENDPOINT_TYPES.get(capability)
	if required is None:
		raise ValueError(f'Unknown AI capability: {capability}')
	needed_inputs = {m.strip().lower() for m in input_modalities if m}
	out: List[CatalogModel] = []
	for model in models:
		endpoints = set(model.endpoint_types)
		if not endpoints & required:
			continue
		if capability == 'chat' and endpoints and endpoints <= NON_TEXT_ENDPOINT_TYPES:
			continue
		if needed_inputs and not needed_inputs <= set(model.input_modalities):
			continue
		out.append(model)
	return tuple(sorted(out, key=lambda m: m.id))


def chat_models(models: Iterable[CatalogModel]) -> Tuple[CatalogModel, ...]:
	"""Convenience wrapper for the text chat / agent entry point."""
	return filter_models(models, capability='chat')


# ---------------------------------------------------------------------------
# Live catalog
# ---------------------------------------------------------------------------

def _cache_key(api_base: str, api_key: str) -> str:
	# Digest, not the key itself: cache bookkeeping must never hold a credential.
	digest = hashlib.sha256(f'{api_base}|{api_key}'.encode('utf-8')).hexdigest()
	return digest[:32]


def _remember_context_windows(models: Iterable[CatalogModel]) -> None:
	for model in models:
		_KNOWN_MODEL_IDS.add(model.id)
		if model.context_length:
			_KNOWN_CONTEXT_WINDOWS[model.id] = model.context_length


def get_known_context_window(model_id: str) -> Optional[int]:
	"""Return a catalog-verified context window for ``model_id``, if known.

	Populated by live discovery and by the verified seed, so context accounting
	works for gateway models litellm has never heard of.
	"""
	if not model_id:
		return None
	if model_id in _KNOWN_CONTEXT_WINDOWS:
		return _KNOWN_CONTEXT_WINDOWS[model_id]
	# Accept a litellm-wrapped id as well (``openai/deepseek/deepseek-v4-pro``).
	if model_id.startswith('openai/'):
		return _KNOWN_CONTEXT_WINDOWS.get(model_id[len('openai/'):])
	return None


def _read_body(response, max_bytes: int) -> bytes:
	content_length = None
	try:
		content_length = response.headers.get('Content-Length')
	except AttributeError:
		content_length = None
	if content_length:
		try:
			if int(content_length) > max_bytes:
				raise CatalogError('Model catalog response is too large.', kind='invalid_response')
		except ValueError:
			pass
	chunks: List[bytes] = []
	total = 0
	for chunk in response.iter_content(chunk_size=65536):
		if not chunk:
			continue
		total += len(chunk)
		if total > max_bytes:
			raise CatalogError('Model catalog response exceeded the size limit.', kind='invalid_response')
		chunks.append(chunk)
	return b''.join(chunks)


def fetch_catalog(api_key: str, provider_id: str = 'orcarouter', api_base: Optional[str] = None,
				  timeout: float = DEFAULT_TIMEOUT, max_items: int = MAX_CATALOG_ITEMS,
				  session=None, capability: str = 'chat') -> Tuple[CatalogModel, ...]:
	"""Fetch and filter the provider's live model catalog.

	``GET {api_base}/models?capability=<capability>`` with the user's Bearer key.
	The request is bounded in time, bytes and item count, and the response is
	never trusted beyond the OpenAI-compatible ``data[]`` shape.
	"""
	spec = require_provider(provider_id)
	if capability != 'chat':
		# Every current secator entry point is a chat entry; other capabilities are
		# filtered locally from the same catalog when they are added.
		raise ValueError(f'Unsupported catalog capability: {capability}')
	if not api_key:
		raise ProviderConfigError(
			f'An {spec.label} API key is required to load the model catalog '
			f'(set addons.ai.api_key or {spec.env_key}).'
		)
	base = validate_api_base(api_base or spec.default_api_base)
	session = session or get_session()
	url = f'{base}/models'

	try:
		response = session.get(
			url,
			headers={'Authorization': f'Bearer {api_key}', 'Accept': 'application/json'},
			params={'capability': capability},
			timeout=(3.05, timeout),
			stream=True,
		)
	except Exception as e:  # requests raises a broad family of transport errors
		kind = 'timeout' if 'timeout' in type(e).__name__.lower() else 'network'
		raise CatalogError(
			f'Could not reach the {spec.label} model catalog ({kind}).',
			kind=kind,
		) from None

	try:
		status = getattr(response, 'status_code', 0)
		if status in (401, 403):
			raise CatalogError(
				f'{spec.label} rejected the API key (HTTP {status}). '
				f'Check or create a key at {spec.console_url}.',
				status=status, kind='auth',
			)
		if status == 429:
			raise CatalogError(
				f'{spec.label} rate-limited the catalog request (HTTP 429). Try again shortly.',
				status=status, kind='rate_limit',
			)
		if status >= 400:
			raise CatalogError(
				f'{spec.label} model catalog returned HTTP {status}.', status=status, kind='http',
			)
		try:
			payload = _read_body(response, MAX_CATALOG_BYTES)
		except CatalogError:
			raise
		except Exception:
			raise CatalogError(
				f'Could not read the {spec.label} model catalog response.', kind='network',
			) from None
	finally:
		try:
			response.close()
		except Exception:
			pass

	try:
		data = json.loads(payload.decode('utf-8'))
	except (UnicodeDecodeError, json.JSONDecodeError):
		raise CatalogError(
			f'{spec.label} model catalog returned malformed JSON.', kind='invalid_response',
		) from None

	records = data.get('data') if isinstance(data, dict) else data
	if not isinstance(records, list):
		raise CatalogError(
			f'{spec.label} model catalog returned an unexpected shape.', kind='invalid_response',
		)

	parsed: List[CatalogModel] = []
	for record in records[:max_items]:
		model = parse_model_record(record)
		if model is not None:
			parsed.append(model)
	models = filter_models(parsed, capability=capability)
	if not models:
		raise CatalogError(
			f'{spec.label} model catalog returned no text-chat models.', kind='empty',
		)
	_remember_context_windows(models)
	return models


def get_catalog(api_key: str, provider_id: str = 'orcarouter', api_base: Optional[str] = None,
				force: bool = False, timeout: float = DEFAULT_TIMEOUT,
				session=None) -> CatalogResult:
	"""Return the chat model options, with cache and degraded fallbacks.

	Order of preference:

	1. a fresh live catalog (in-process TTL cache);
	2. the last live catalog seen for this base (``last_known_good``);
	3. the small verified seed (``fallback``).

	Neither fallback can be reached when live discovery succeeded: the live
	result is authoritative for the call.
	"""
	spec = require_provider(provider_id)
	base = validate_api_base(api_base or spec.default_api_base)
	cache_key = _cache_key(base, api_key)
	now = time.monotonic()

	if not force:
		cached = _CATALOG_CACHE.get(cache_key)
		if cached and now - cached[0] < CATALOG_CACHE_TTL:
			return CatalogResult(models=cached[1], source='live', degraded=False)

	try:
		models = fetch_catalog(api_key, provider_id=provider_id, api_base=base,
							   timeout=timeout, session=session)
	except CatalogError as e:
		known = _LAST_KNOWN_GOOD.get(base) or ()
		if known:
			return CatalogResult(models=known, source='last_known_good', degraded=True, error=str(e))
		return CatalogResult(models=VERIFIED_FALLBACK_MODELS, source='fallback', degraded=True, error=str(e))

	_CATALOG_CACHE[cache_key] = (now, models)
	_LAST_KNOWN_GOOD[base] = models
	return CatalogResult(models=models, source='live', degraded=False)


def reset_caches() -> None:
	"""Clear in-process catalog state (tests and explicit refresh)."""
	_CATALOG_CACHE.clear()
	_LAST_KNOWN_GOOD.clear()
	_KNOWN_CONTEXT_WINDOWS.clear()
	_KNOWN_MODEL_IDS.clear()
	_remember_context_windows(VERIFIED_FALLBACK_MODELS)


def describe_model(model: CatalogModel) -> str:
	"""One-line selector label with the metadata the catalog advertised."""
	bits = [model.id]
	if model.context_length:
		bits.append(f'ctx {model.context_length:,}')
	bits.append('input ' + ','.join(model.input_modalities))
	if model.reasoning and model.reasoning_efforts:
		bits.append('reasoning ' + '/'.join(model.reasoning_efforts))
	return '  ·  '.join(bits)


# Seed the verified metadata immediately so context accounting works before the
# first live discovery (cold start / offline install).
_remember_context_windows(VERIFIED_FALLBACK_MODELS)
