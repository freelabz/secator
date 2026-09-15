import json
from urllib.parse import urljoin, urlparse, urlunparse

import requests
import yaml

from secator.config import CONFIG
from secator.decorators import task
from secator.definitions import HEADER
from secator.output_types import Info, Url, Warning
from secator.runners import PythonRunner
from secator.utils import headers_to_dict

# Paths a Swagger / OpenAPI document is commonly served from, tried in order when the input URL is
# not itself a spec (e.g. it points at the Swagger UI HTML page or at the bare host).
SPEC_CANDIDATE_PATHS = [
	'/openapi.json', '/openapi.yaml',
	'/v3/api-docs', '/v2/api-docs', '/api-docs',
	'/swagger.json', '/swagger.yaml',
	'/swagger/v1/swagger.json', '/swagger/v2/swagger.json',
	'/swagger/docs/v1', '/swagger/docs/v2',  # Swashbuckle (classic .NET)
	'/v1/swagger.json', '/v2/swagger.json',
	'/api/swagger.json', '/api/openapi.json', '/api-docs/swagger.json',
]

# Methods that carry a request body: the whole point of the export is to describe these for a caller
# (a human or an AI) that will craft the actual requests.
BODY_METHODS = {'post', 'put', 'patch', 'delete'}
HTTP_METHODS = {'get', 'head', 'options', 'trace'} | BODY_METHODS


@task()
class swaggerparser(PythonRunner):
	"""Parse a Swagger / OpenAPI spec and emit one URL per (path, method) with its parameters and request body schema."""  # noqa: E501
	input_types = [Url.__name__.lower()]
	output_types = [Url]
	tags = ['api', 'openapi', 'recon']
	# swaggerparser only fetches the spec document itself; it never sends requests to the described
	# endpoints, so most HTTP knobs do not apply. The custom header is the exception: it is needed to
	# fetch a spec that sits behind authentication (same "KEY1:VALUE1;; KEY2:VALUE2" syntax as the
	# HTTP tasks). PythonRunner.get_opt_value does not run pre_process, so yielder() splits it itself.
	opts = {
		HEADER: {'type': str, 'short': 'H', 'help': 'Custom header(s) to fetch the spec, "KEY1:VALUE1;; KEY2:VALUE2"'},  # noqa: E501
		'insecure': {'is_flag': True, 'default': False, 'help': 'Allow fetching the spec over insecure / self-signed TLS'},  # noqa: E501
		'spec_timeout': {'type': int, 'default': 10, 'help': 'Timeout (seconds) for fetching the spec'},
	}
	profile = 'small'

	def yielder(self):
		insecure = self.get_opt_value('insecure')
		timeout = self.get_opt_value('spec_timeout')
		headers = headers_to_dict(self.get_opt_value(HEADER)) if self.get_opt_value(HEADER) else {}

		for target in self.inputs:
			spec_url, spec, tried = self._resolve_spec(target, headers, insecure, timeout)
			if spec is None:
				# Never fail silently: list what was fetched so the real spec URL can be spotted.
				yield Warning(message=f'No OpenAPI / Swagger spec found from {target}. Tried {len(tried)} URL(s): ' + ', '.join(tried[:12]) + ('...' if len(tried) > 12 else ''))  # noqa: E501
				continue

			yield Info(message=f'Spec loaded from {spec_url} (OpenAPI/Swagger)')
			base_url = self._base_url(spec, spec_url)
			count = 0
			for url_obj in self._iter_operations(spec, base_url):
				count += 1
				yield url_obj
			yield Info(message=f'Parsed {count} operations from {spec_url}')

	# -- spec discovery ------------------------------------------------------------------------

	def _resolve_spec(self, target, headers, insecure, timeout):
		"""Return (spec_url, parsed_spec, tried) resolving the real spec even when *target* points at
		the Swagger UI HTML page or at the bare host. *tried* is the list of URLs fetched, for
		diagnostics. Returns (None, None, tried) when nothing parses."""
		tried = []

		def try_url(url):
			"""Fetch *url*; return a parsed spec, or follow a Swagger UI config (swagger-config.json,
			which lists specs under `url` / `urls`) one level down. Returns (spec_url, spec) or None."""
			tried.append(url)
			body, ctype = self._fetch(url, headers, insecure, timeout)
			if body is None:
				return None
			spec = self._parse_spec(body)
			if spec:
				return url, spec
			# A swagger-config.json points at the real spec(s) rather than being one.
			for nested in self._spec_urls_from_config(body, url):
				if nested in tried:
					continue
				tried.append(nested)
				sub_body, _ = self._fetch(nested, headers, insecure, timeout)
				if sub_body:
					nested_spec = self._parse_spec(sub_body)
					if nested_spec:
						return nested, nested_spec
			# An HTML Swagger UI page: follow every spec / config URL it references.
			if 'html' in (ctype or '') or '<html' in body[:400].lower() or body.lstrip().lower().startswith('<!doctype'):  # noqa: E501
				for found in self._spec_urls_from_html(body, url):
					if found in tried:
						continue
					got = try_url(found)
					if got:
						return got
			return None

		# 1. The target itself (spec, config, or Swagger UI page).
		got = try_url(target)
		if got:
			return got[0], got[1], tried

		# 2. Autodiscovery over well-known paths, tried both at the origin and relative to the
		#    target's path prefix (e.g. a "/swagger/..." mount -> "/swagger/v1/swagger.json").
		parsed = urlparse(target)
		origin = urlunparse((parsed.scheme or 'https', parsed.netloc or parsed.path, '', '', '', ''))
		bases = [origin]
		# Path prefixes: /swagger/ui/index -> ['/swagger/ui', '/swagger']
		segments = [seg for seg in parsed.path.split('/') if seg]
		for i in range(len(segments) - 1, 0, -1):
			bases.append(origin + '/' + '/'.join(segments[:i]))
		seen = set()
		for base in bases:
			for path in SPEC_CANDIDATE_PATHS:
				candidate = base.rstrip('/') + path
				if candidate in seen:
					continue
				seen.add(candidate)
				got = try_url(candidate)
				if got:
					return got[0], got[1], tried
		return None, None, tried

	def _fetch(self, url, headers, insecure, timeout):
		"""Return (text, content_type) or (None, None) on any failure / non-2xx."""
		# Send a browser User-Agent by default: a WAF in front of a real site blocks the
		# `python-requests/x` default outright, which would make every fetch fail silently. The
		# caller's own headers (e.g. an auth cookie) take precedence.
		req_headers = {'User-Agent': CONFIG.http.default_header.split(':', 1)[-1].strip(), 'Accept': '*/*'}
		req_headers.update(headers or {})
		try:
			resp = requests.get(url, headers=req_headers, verify=not insecure, timeout=timeout, allow_redirects=True)  # noqa: E501
		except requests.RequestException:
			return None, None
		if resp.status_code >= 400:
			return None, None
		return resp.text, resp.headers.get('Content-Type', '')

	@staticmethod
	def _parse_spec(body):
		"""Parse JSON or YAML and return the doc only if it looks like OpenAPI/Swagger."""
		doc = None
		try:
			doc = json.loads(body)
		except (ValueError, TypeError):
			try:
				doc = yaml.safe_load(body)
			except yaml.YAMLError:
				return None
		if not isinstance(doc, dict):
			return None
		if 'openapi' in doc or 'swagger' in doc or ('paths' in doc and isinstance(doc['paths'], dict)):
			return doc
		return None

	@staticmethod
	def _spec_urls_from_html(html, page_url):
		"""Yield every spec / config URL a Swagger UI / Redoc page references, resolved against the
		page URL. Includes configUrl (a swagger-config.json to follow)."""
		import re
		patterns = [
			r'''url\s*:\s*["']([^"']+)["']''',          # SwaggerUIBundle({ url: "..." })
			r'''configUrl\s*:\s*["']([^"']+)["']''',    # SwaggerUIBundle({ configUrl: "..." })
			r'''spec-url\s*=\s*["']([^"']+)["']''',     # <redoc spec-url="...">
			r'''["']([^"']*(?:swagger|openapi|api-docs)[^"']*\.(?:json|yaml|yml))["']''',  # spec-looking href
		]
		seen = []
		for pat in patterns:
			for m in re.finditer(pat, html, re.IGNORECASE):
				val = m.group(1)
				low = val.lower()
				if low.endswith(('.js', '.css', '.png', '.ico', '.map')):
					continue
				if not any(k in low for k in ('swagger', 'openapi', 'api-docs', 'api/docs', 'config', '.json', '.yaml', '.yml')):  # noqa: E501
					continue
				resolved = urljoin(page_url, val)
				if resolved not in seen:
					seen.append(resolved)

		# Classic Swashbuckle (.NET) builds the spec URL in JS as
		# `swashbuckleConfig.rootUrl + "/" + swashbuckleConfig.discoveryPaths[i]` — never a literal
		# string. Reconstruct it from the discoveryPaths array (rootUrl falls back to the page origin).
		root_m = re.search(r'rootUrl\s*[:=]\s*[\'"]([^\'"]+)[\'"]', html)
		paths_m = re.search(r'discoveryPaths\s*[:=]\s*(?:arrayFrom\()?\s*\[?\s*([^\]);]+)', html)
		if paths_m:
			disc = re.findall(r'[\'"]([^\'"]+)[\'"]', paths_m.group(1))
			root = root_m.group(1).rstrip('/') if root_m else None
			for d in disc:
				d = d.strip()
				if not d:
					continue
				built = (root + '/' + d.lstrip('/')) if root else urljoin(page_url, d.lstrip('/'))
				if built not in seen:
					seen.append(built)
		return seen

	@staticmethod
	def _spec_urls_from_config(body, config_url):
		"""If *body* is a Swagger UI config (swagger-config.json: {url: ...} or {urls: [{url,...}]}),
		return the spec URLs it points at, resolved against the config URL. Otherwise []."""
		try:
			doc = json.loads(body)
		except (ValueError, TypeError):
			return []
		if not isinstance(doc, dict):
			return []
		out = []
		if isinstance(doc.get('url'), str):
			out.append(urljoin(config_url, doc['url']))
		for entry in doc.get('urls', []) or []:
			if isinstance(entry, dict) and isinstance(entry.get('url'), str):
				out.append(urljoin(config_url, entry['url']))
		return out

	# -- base URL ------------------------------------------------------------------------------

	@staticmethod
	def _base_url(spec, spec_url):
		"""Resolve the server base URL. OpenAPI 3 uses `servers`, Swagger 2 uses host + basePath."""
		parsed = urlparse(spec_url)
		origin = urlunparse((parsed.scheme, parsed.netloc, '', '', '', ''))
		servers = spec.get('servers')
		if servers and isinstance(servers, list) and servers[0].get('url'):
			server = servers[0]['url']
			# A relative server url (e.g. "/api/v2") is resolved against the spec origin.
			return server.rstrip('/') if server.startswith('http') else origin + '/' + server.strip('/')
		if spec.get('host'):
			scheme = (spec.get('schemes') or [parsed.scheme or 'https'])[0]
			base_path = spec.get('basePath', '') or ''
			return f'{scheme}://{spec["host"]}{base_path}'.rstrip('/')
		return origin

	# -- operations ----------------------------------------------------------------------------

	def _iter_operations(self, spec, base_url):
		paths = spec.get('paths') or {}
		for path, path_item in paths.items():
			if not isinstance(path_item, dict):
				continue
			# Parameters declared at the path level apply to every operation under it.
			shared_params = path_item.get('parameters', []) or []
			for method, operation in path_item.items():
				if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
					continue
				yield self._build_url(spec, base_url, path, method.lower(), operation, shared_params)

	def _build_url(self, spec, base_url, path, method, operation, shared_params):
		full_url = base_url.rstrip('/') + '/' + path.lstrip('/')
		all_params = shared_params + (operation.get('parameters', []) or [])
		params = [self._describe_param(spec, p) for p in all_params]
		params = [p for p in params if p]

		extra_data = {
			'method': method.upper(),
			'operation_id': operation.get('operationId', ''),
			'summary': operation.get('summary', ''),
			'tags': operation.get('tags', []),
		}
		query_params = [p for p in params if p.get('in') == 'query']
		path_params = [p for p in params if p.get('in') == 'path']
		header_params = [p for p in params if p.get('in') == 'header']
		if query_params:
			extra_data['query_params'] = query_params
		if path_params:
			extra_data['path_params'] = path_params
		if header_params:
			extra_data['header_params'] = header_params

		# Request body: the payload an AI / operator needs to craft POST/PUT/PATCH requests.
		if method in BODY_METHODS:
			body = self._describe_body(spec, operation.get('requestBody'), operation)
			if body:
				extra_data['content_type'] = body['content_type']
				extra_data['body_schema'] = body['schema']
				if body['required']:
					extra_data['required'] = body['required']
				extra_data['body_example'] = body['example']

		return Url(
			url=full_url,
			method=method.upper(),
			confidence='high',
			extra_data=extra_data,
			tags=['openapi'],
		)

	@staticmethod
	def _describe_param(spec, param):
		param = swaggerparser._resolve_ref(spec, param)
		if not isinstance(param, dict) or 'name' not in param:
			return None
		schema = param.get('schema', {}) or {}
		return {
			'name': param['name'],
			'in': param.get('in', 'query'),
			'required': bool(param.get('required', False)),
			'type': schema.get('type', param.get('type', 'string')),
		}

	def _describe_body(self, spec, request_body, operation):
		# OpenAPI 3: requestBody.content.<ctype>.schema
		request_body = self._resolve_ref(spec, request_body) if request_body else None
		if request_body and isinstance(request_body, dict):
			content = request_body.get('content', {}) or {}
			for ctype in ('application/json', *content.keys()):
				if ctype in content:
					schema = self._resolve_ref(spec, content[ctype].get('schema', {}))
					required = schema.get('required', []) if isinstance(schema, dict) else []
					return {
						'content_type': ctype,
						'schema': self._simplify_schema(spec, schema),
						'required': required,
						'example': self._example_from_schema(spec, schema),
					}
		# Swagger 2: a body parameter with a schema.
		for param in operation.get('parameters', []) or []:
			param = self._resolve_ref(spec, param)
			if isinstance(param, dict) and param.get('in') == 'body':
				schema = self._resolve_ref(spec, param.get('schema', {}))
				required = schema.get('required', []) if isinstance(schema, dict) else []
				return {
					'content_type': 'application/json',
					'schema': self._simplify_schema(spec, schema),
					'required': required,
					'example': self._example_from_schema(spec, schema),
				}
		return None

	# -- schema helpers ------------------------------------------------------------------------

	@staticmethod
	def _resolve_ref(spec, node, _depth=0):
		"""Resolve a local $ref (e.g. #/components/schemas/User) against the root doc."""
		if _depth > 20 or not isinstance(node, dict):
			return node
		ref = node.get('$ref')
		if not ref or not ref.startswith('#/'):
			return node
		target = spec
		for part in ref[2:].split('/'):
			if not isinstance(target, dict):
				return {}
			target = target.get(part, {})
		return swaggerparser._resolve_ref(spec, target, _depth + 1)

	def _simplify_schema(self, spec, schema, _depth=0):
		"""Return a compact {field: type} view of an object schema (one level, refs resolved)."""
		schema = self._resolve_ref(spec, schema)
		if not isinstance(schema, dict) or _depth > 5:
			return {}
		if schema.get('type') == 'object' or 'properties' in schema:
			out = {}
			for name, prop in (schema.get('properties', {}) or {}).items():
				prop = self._resolve_ref(spec, prop)
				ptype = prop.get('type', 'string')
				if ptype == 'object':
					out[name] = self._simplify_schema(spec, prop, _depth + 1)
				elif ptype == 'array':
					items = self._resolve_ref(spec, prop.get('items', {}))
					out[name] = [items.get('type', 'string')]
				else:
					out[name] = ptype
			return out
		if schema.get('type') == 'array':
			items = self._resolve_ref(spec, schema.get('items', {}))
			return [self._simplify_schema(spec, items, _depth + 1) if items.get('type') == 'object' else items.get('type', 'string')]  # noqa: E501
		return {'type': schema.get('type', 'string')}

	def _example_from_schema(self, spec, schema, _depth=0):
		"""Build a plausible example payload from a schema so a caller has a ready-to-edit body."""
		schema = self._resolve_ref(spec, schema)
		if not isinstance(schema, dict) or _depth > 5:
			return None
		if 'example' in schema:
			return schema['example']
		if 'default' in schema:
			return schema['default']
		if 'enum' in schema and schema['enum']:
			return schema['enum'][0]
		stype = schema.get('type')
		if stype == 'object' or 'properties' in schema:
			return {
				name: self._example_from_schema(spec, prop, _depth + 1)
				for name, prop in (schema.get('properties', {}) or {}).items()
			}
		if stype == 'array':
			return [self._example_from_schema(spec, schema.get('items', {}), _depth + 1)]
		return swaggerparser._scalar_example(schema)

	@staticmethod
	def _scalar_example(schema):
		stype = schema.get('type', 'string')
		fmt = schema.get('format', '')
		if stype == 'integer':
			return 0
		if stype == 'number':
			return 0.0
		if stype == 'boolean':
			return True
		examples = {
			'email': 'user@example.com', 'date-time': '2020-01-01T00:00:00Z', 'date': '2020-01-01',
			'uuid': '00000000-0000-0000-0000-000000000000', 'uri': 'https://example.com',
			'password': 'P@ssw0rd!', 'byte': 'ZXhhbXBsZQ==', 'ipv4': '127.0.0.1',
		}
		return examples.get(fmt, 'string')
