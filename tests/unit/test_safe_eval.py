import unittest

from dotmap import DotMap

from secator.safe_eval import safe_eval_condition

FUNCS = {'len': len}

# Fixtures shared by the corpus below: one DotMap per condition-DSL variable
# name real conditions bind to (item/opts/port/url/ip/target), plus targets.
NAMES = {
	'ip': DotMap({'alive': True}),
	'item': DotMap({
		'id': 'item-1',
		'is_directory': True,
		'name': 'net_cidr',
		'status_code': 200,
		'stored_response_path': '/tmp/resp.html',
		'type': 'url',
		'verified': False,
		'_source': 'gf_urls',
		'_context': {'scope': 'example.com', 'ancestor_id': 'abc'},
	}),
	'opts': DotMap({
		'probe': False,
		'ports': '80,443',
		'scanners': True,
		'hunt_secrets': True,
		'fuzzers': ['arjun'],
		'crawlers': ['cariddi'],
		'passive': False,
		'mode': 'filesystem',
		'brute_dns': True,
		'nuclei': True,
	}),
	'port': DotMap({'host': '10.0.0.1', 'port': 22, 'service_name': 'SSH'}),
	'url': DotMap({'verified': False, 'is_root': True}),
	'target': DotMap({'type': 'domain'}),
	'targets': ['10.0.0.1'],
}

# (condition, expected result)
VALID_CONDITIONS = [
	('ip.alive', True),
	('item.id', 'item-1'),
	('item.is_directory', True),
	("item.name == 'email_address'", False),
	("item.name in ['lfi']", False),
	("item.name == 'net_cidr' and len(targets) == 0", False),
	('item._source.startswith("gf")', True),
	("item._source.startswith('urlparser') or item._source.startswith('arjun') or item._source.startswith('x8')", False),  # noqa: E501
	('item.status_code != 0', True),
	("item.stored_response_path != ''", True),
	("item.type == 'url'", True),
	('not item.verified', True),
	('not opts.probe', True),
	('not url.verified or opts.hunt_secrets', True),
	('opts.ports', '80,443'),
	('port.host in targets and opts.scanners', True),
	("port.port == 22 or 'ssh' in port.service_name.lower()", True),
	("target.type != 'email'", True),
	('url.is_root', True),
	('item._context.get("scope") == "example.com"', True),
	("'arjun' in opts.fuzzers", True),
	("'cariddi' in opts.crawlers and not opts.passive", True),
	('len(targets) == 0', False),
	("not opts.mode or opts.mode in ['filesystem', 'git']", True),
	('opts.brute_dns and not opts.passive', True),
	('opts.nuclei and not opts.passive', True),
]

INVALID_EXPRESSIONS = [
	'item.__class__',
	'opts.mode.__class__.__base__',
	'[x for x in targets]',
	'(lambda: 1)()',
	"open('/etc/passwd')",
	'unknown_name == 1',
	"opts.mode.format('x')",
]


class TestSafeEvalCorpus(unittest.TestCase):
	"""Every real condition used across workflow/scan/tree configs must evaluate."""

	def test_valid_conditions_accepted(self):
		for expr, expected in VALID_CONDITIONS:
			with self.subTest(expr=expr):
				self.assertEqual(safe_eval_condition(expr, NAMES, FUNCS), expected)


class TestSafeEvalRejectsOutsideDSL(unittest.TestCase):
	"""Constructs outside the condition DSL must be rejected, not silently run."""

	def test_disallowed_constructs_raise(self):
		for expr in INVALID_EXPRESSIONS:
			with self.subTest(expr=expr):
				with self.assertRaises(ValueError):
					safe_eval_condition(expr, NAMES, FUNCS)




if __name__ == '__main__':
	unittest.main()
