"""Technology identity: catalog normalizer + the tasks that emit Technology."""
import os
import tempfile
import unittest

from secator.output_types import Port, Technology
from secator.technology import catalog, cpe23, lookup, normalize_technology, split_version, version_cpe

# (expected key, expected display name, raw spellings from different tools / advisories)
CASES = [
	('apache:http_server', 'Apache HTTP Server', [
		('Apache HTTP Server', None),        # wappalyzer
		('Apache', None),                    # Server header
		('Apache/2.4.25 (Debian)', None),    # Server header with version
		('apache httpd', None),              # nmap -sV
		('apache', None),                    # nuclei apache-detect
		('HTTP Server', 'Apache'),           # advisory vendor + product
		('Apache', 'Apache'),
	]),
	('f5:nginx', 'nginx', [('Nginx', None), ('nginx/1.31.8', None), ('nginx/1.18.0 (Ubuntu)', None), ('NGINX', 'F5')]),
	('microsoft:internet_information_services', 'Microsoft IIS', [
		('IIS', None), ('Microsoft-IIS/10.0', None), ('microsoft iis httpd', None), ('ms-iis', None),
		('microsoft iis', None), ('Internet Information Services (IIS)', 'Microsoft')]),
	('openbsd:openssh', 'OpenSSH', [('openssh', None), ('OpenSSH server', None), ('OpenSSH', 'OpenBSD')]),
	('php:php', 'PHP', [('PHP', None), ('php', None), ('PHP', 'PHP Group'), ('FastCGI Process Manager (FPM)', 'PHP')]),
	('jquery:jquery', 'jQuery', [('jQuery', None), ('JQuery', 'JQuery')]),
	('wordpress:wordpress', 'WordPress', [('WordPress', None), ('Core', 'WordPress'), ('WordPress Core', 'WordPress')]),
	('microsoft:exchange_server', 'Microsoft Exchange Server', [
		('Outlook Web App', None), ('ms exchange server', None), ('Exchange Server', 'Microsoft'), ('Exchange', 'Microsoft')]),  # noqa: E501
	('oracle:weblogic_server', 'Oracle WebLogic Server', [
		('oracle weblogic admin httpd', None), ('weblogic server', 'oracle'), ('WebLogic Server', 'Oracle')]),
	('synology:diskstation_manager', 'Synology DiskStation Manager', [
		('Synology DiskStation', None), ('DiskStation Manager (DSM)', 'Synology')]),
]

# Spellings that must NOT resolve to the given key (or must stay unknown when key is None).
NEGATIVES = [
	('Apache Tomcat', None, 'apache:http_server'),
	('Apache-Coyote/1.1', None, 'apache:http_server'),
	('Struts', 'Apache', 'apache:http_server'),
	('Roller', 'Apache', 'apache:http_server'),
	('ActiveMQ', 'Apache', 'apache:http_server'),
	('HTTP Server and Oracle Weblogic Server Proxy Plug-in', 'Oracle', 'apache:http_server'),
	('jQuery UI', None, 'jquery:jquery'),
	('jQuery CDN', None, 'jquery:jquery'),
	('File Manager Plugin', 'WordPress', 'wordpress:wordpress'),
	('Google Tag Manager for WordPress', None, 'wordpress:wordpress'),
	('PHPMailer', 'PHP', 'php:php'),
	('HTTP/3', None, None),
	('HTTP/2', 'IETF', None),
	('Platform.sh', None, None),
	('Platform', 'XWiki', None),
	('Microsoft', 'Microsoft', None),
	('Apache', 'Oracle', 'apache:http_server'),
]


class TestTechnologyCatalog(unittest.TestCase):

	def test_canonical_identity_for_every_spelling(self):
		for key, name, spellings in CASES:
			for raw, vendor in spellings:
				with self.subTest(raw=raw, vendor=vendor):
					norm = normalize_technology(raw, vendor=vendor)
					self.assertEqual(norm['key'], key)
					self.assertEqual(norm['product'], name)

	def test_near_misses_do_not_resolve(self):
		for raw, vendor, forbidden in NEGATIVES:
			with self.subTest(raw=raw, vendor=vendor):
				key, _ = lookup(raw, vendor)
				if forbidden:
					self.assertNotEqual(key, forbidden)
				else:
					self.assertIsNone(key)

	def test_tomcat_spellings(self):
		self.assertEqual(lookup('Apache-Coyote/1.1')[0], 'apache:tomcat')
		self.assertEqual(lookup('Tomcat', 'Apache')[0], 'apache:tomcat')
		# the Coyote number is the connector protocol, not a Tomcat release
		self.assertIsNone(normalize_technology('Apache-Coyote/1.1')['version'])

	def test_fuzzy_maps_only_into_the_catalog(self):
		key, method = lookup('Synology DiskStation Mgr')
		self.assertEqual((key, method), ('synology:diskstation_manager', 'fuzzy'))
		self.assertEqual(lookup('Totally Unknown Thing'), (None, None))
		# vendor must agree
		self.assertIsNone(lookup('Exchange Server', 'Acme')[0])

	def test_split_version(self):
		self.assertEqual(split_version('nginx/1.30.4'), ('nginx', '1.30.4'))
		self.assertEqual(split_version('Apache/2.4.25 (Debian)'), ('Apache', '2.4.25'))
		self.assertEqual(split_version('Apache HTTP Server:2.4.56'), ('Apache HTTP Server', '2.4.56'))
		self.assertEqual(split_version('Microsoft-IIS/8.5'), ('Microsoft-IIS', '8.5'))
		self.assertEqual(split_version('12.2.1.3.0'), ('', '12.2.1.3.0'))
		self.assertEqual(split_version('Outlook Web App'), ('Outlook Web App', None))
		self.assertEqual(split_version('Apache/2.4.58 (Unix) OpenSSL/3.0.2'), ('Apache', '2.4.58'))

	def test_unknown_product_keeps_its_suffix(self):
		self.assertEqual(normalize_technology('Acme Widget (Cloud)')['product'], 'Acme Widget (Cloud)')
		self.assertEqual(normalize_technology('Acme/1.2 (Debian)')['product'], 'Acme')
		self.assertEqual(normalize_technology('nginx (Ubuntu)')['key'], 'f5:nginx')  # known: suffix ignored

	def test_cpe_names_the_product(self):
		norm = normalize_technology('weird banner', cpes=['cpe:/a:igor_sysoev:nginx:1.19.0'])
		self.assertEqual((norm['key'], norm['method']), ('f5:nginx', 'cpe'))
		# a CPE vendor given as the vendor agrees with the entry
		self.assertEqual(normalize_technology('nginx', vendor='igor_sysoev')['key'], 'f5:nginx')
		norm = normalize_technology('caddy httpd', cpes=['cpe:/a:matt_holt:caddy', 'cpe:/o:linux:linux_kernel'])
		self.assertEqual(norm['key'], 'matt_holt:caddy')

	def test_catalog_flags(self):
		self.assertTrue(catalog()['entries']['microsoft:windows']['requires_version'])
		self.assertEqual(lookup('Windows Server')[0], 'microsoft:windows')

	def test_output_type_normalizes_and_keeps_raw(self):
		t = Technology(match='http://scanme.nmap.org', product='Apache/2.4.7 (Ubuntu)')
		self.assertEqual((t.product, t.version, t.vendor, t.key),
						 ('Apache HTTP Server', '2.4.7', 'apache', 'apache:http_server'))
		self.assertEqual(t.extra_data['raw_product'], 'Apache/2.4.7 (Ubuntu)')
		t = Technology(match='x', product='Some Library', version='1.0')
		self.assertEqual((t.product, t.key), ('Some Library', ''))


IIS_CPE = 'cpe:2.3:a:microsoft:internet_information_services:8.5:*:*:*:*:*:*:*'


class TestTechnologyCpe(unittest.TestCase):
	"""The CPE a vulnerability lookup uses: the tool's own when it has a version, else key + version."""

	def test_cpe23_from_cpe22(self):
		self.assertEqual(cpe23('cpe:/a:microsoft:internet_information_services:8.5'), IIS_CPE)
		self.assertEqual(cpe23('cpe:/a:igor_sysoev:nginx:1.18.0'), 'cpe:2.3:a:igor_sysoev:nginx:1.18.0:*:*:*:*:*:*:*')
		self.assertEqual(cpe23('cpe:/o:linux:linux_kernel'), 'cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*')
		self.assertEqual(cpe23('cpe:/a:acme:widget:1.0%2b1'), r'cpe:2.3:a:acme:widget:1.0\+1:*:*:*:*:*:*:*')
		self.assertEqual(  # packed CPE 2.2 edition
			cpe23('cpe:/a:acme:widget:1.0::~~pro~linux~x64~'),
			'cpe:2.3:a:acme:widget:1.0:*:*:*:pro:linux:x64:*')

	def test_cpe23_passthrough_and_garbage(self):
		self.assertEqual(cpe23(IIS_CPE), IIS_CPE)
		self.assertEqual(cpe23('cpe:2.3:a:apache:http_server:2.4.7'), 'cpe:2.3:a:apache:http_server:2.4.7:*:*:*:*:*:*:*')
		for bad in (None, '', 'Microsoft-IIS 8.5', 'cpe:/a', 'cpe:2.3:a'):
			self.assertIsNone(cpe23(bad))

	def test_tool_cpe_with_version_wins(self):
		cpes = ['cpe:/a:microsoft:internet_information_services:8.5', 'cpe:/o:microsoft:windows']
		self.assertEqual(version_cpe('8.5', 'microsoft:internet_information_services', cpes), IIS_CPE)
		# A legacy CPE vendor the catalog knows the product under still counts as the same product.
		self.assertEqual(version_cpe('1.18.0', 'f5:nginx', ['cpe:/a:igor_sysoev:nginx:1.18.0']),
						 'cpe:2.3:a:igor_sysoev:nginx:1.18.0:*:*:*:*:*:*:*')

	def test_built_from_key_when_no_tool_cpe(self):
		self.assertEqual(version_cpe('8.5', 'microsoft:internet_information_services'), IIS_CPE)
		# A versionless tool CPE, an OS CPE, or another product's CPE is not used.
		self.assertEqual(version_cpe('8.5', 'microsoft:internet_information_services',
									 ['cpe:/a:microsoft:internet_information_services', 'cpe:/o:microsoft:windows',
									  'cpe:/a:php:php:5.6']), IIS_CPE)
		self.assertEqual(version_cpe('1.0 beta', 'acme:widget'), r'cpe:2.3:a:acme:widget:1.0\ beta:*:*:*:*:*:*:*')

	def test_no_cpe_without_version_or_identity(self):
		self.assertEqual(version_cpe(None, 'microsoft:internet_information_services'), '')
		self.assertEqual(version_cpe('', '', ['cpe:/a:microsoft:internet_information_services:8.5']), '')
		self.assertEqual(version_cpe('1.0', ''), '')

	def test_technology_cpe(self):
		# Server header: no CPE from the tool, built from the catalog key.
		t = Technology(match='http://host', product='Microsoft-IIS/8.5')
		self.assertEqual((t.product, t.version, t.cpe), ('Microsoft IIS', '8.5', IIS_CPE))
		# nmap: its CPE 2.2 is used.
		t = Technology(match='host:80', product='Microsoft IIS httpd', version='8.5',
					   extra_data={'cpe': ['cpe:/a:microsoft:internet_information_services:8.5', 'cpe:/o:microsoft:windows']})
		self.assertEqual(t.cpe, IIS_CPE)
		# Unknown product, no version, or a fuzzy-matched key: no CPE (free-text lookup instead).
		self.assertEqual(Technology(match='x', product='Some Library', version='1.0').cpe, '')
		self.assertEqual(Technology(match='x', product='Microsoft-IIS').cpe, '')
		t = Technology(match='x', product='Synology DiskStation Mgr', version='7.2')
		self.assertEqual((t.key, t.extra_data.get('key_match'), t.cpe), ('synology:diskstation_manager', 'fuzzy', ''))


NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV scanme.nmap.org" start="1700000000" version="7.94">
<host><status state="up" reason="syn-ack"/>
<address addr="45.33.32.156" addrtype="ipv4"/>
<hostnames><hostname name="scanme.nmap.org" type="user"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>
<service name="ssh" product="OpenSSH" version="6.6.1p1 Ubuntu 2ubuntu2.13" extrainfo="Ubuntu Linux; protocol 2.0" ostype="Linux" method="probed" conf="10">  # noqa: E501
<cpe>cpe:/a:openbsd:openssh:6.6.1p1</cpe><cpe>cpe:/o:linux:linux_kernel</cpe></service></port>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>
<service name="http" product="Apache httpd" version="2.4.7" extrainfo="(Ubuntu)" method="probed" conf="10">
<cpe>cpe:/a:apache:http_server:2.4.7</cpe></service></port>
</ports></host>
<runstats><finished time="1700000010"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>
"""


class TestNmapTechnology(unittest.TestCase):

	def test_technology_keeps_service_cpes(self):
		from secator.tasks.nmap import nmap
		with tempfile.NamedTemporaryFile('w', suffix='.xml', delete=False) as f:
			f.write(NMAP_XML)
		try:
			task = nmap.__new__(nmap)
			task.output_path = f.name
			results = list(task.xml_to_json())
		finally:
			os.unlink(f.name)
		techs = {t.key: t for t in results if isinstance(t, Technology)}
		self.assertTrue(any(isinstance(r, Port) for r in results))
		httpd = techs['apache:http_server']
		self.assertEqual((httpd.product, httpd.version), ('Apache HTTP Server', '2.4.7'))
		self.assertIn('cpe:/a:apache:http_server:2.4.7', httpd.extra_data['cpe'])
		ssh = techs['openbsd:openssh']
		self.assertEqual(ssh.product, 'OpenSSH')
		self.assertIn('cpe:/a:openbsd:openssh:6.6.1p1', ssh.extra_data['cpe'])
		self.assertIn('cpe:/o:linux:linux_kernel', ssh.extra_data['cpe'])
		for tech in techs.values():  # the CPE secator builds from the product string is not kept
			self.assertFalse([c for c in tech.extra_data['cpe'] if ' ' in c])
		# The vulnerability-lookup CPE is nmap's own (CPE 2.2 -> 2.3), not the banner version string.
		self.assertEqual(httpd.cpe, 'cpe:2.3:a:apache:http_server:2.4.7:*:*:*:*:*:*:*')
		self.assertEqual(ssh.cpe, 'cpe:2.3:a:openbsd:openssh:6.6.1p1:*:*:*:*:*:*:*')


def _nuclei_item(template_id, tags, matcher_name=None, extracted=None, metadata=None, cpe=None, severity='info'):
	info = {'name': template_id, 'severity': severity, 'tags': tags, 'metadata': metadata or {}}
	if cpe:
		info['classification'] = {'cpe': cpe}
	item = {'template-id': template_id, 'info': info, 'matched-at': 'http://scanme.nmap.org',
			'host': 'scanme.nmap.org', 'type': 'http', 'template-url': ''}
	if matcher_name:
		item['matcher-name'] = matcher_name
	if extracted:
		item['extracted-results'] = extracted
	return item


class TestNucleiTechnology(unittest.TestCase):

	def _convert(self, item):
		from secator.tasks.nuclei import nuclei, output_discriminator
		cls = output_discriminator(None, item)
		if cls is not Technology:
			return cls
		return Technology.load(item, nuclei.output_map[Technology])

	def test_detections_become_technology(self):
		cases = [
			(_nuclei_item('tech-detect', ['tech', 'discovery'], matcher_name='nginx'),
			 ('nginx', None, 'f5:nginx')),
			(_nuclei_item('tech-detect', ['tech', 'discovery'], matcher_name='ms-iis'),
			 ('Microsoft IIS', None, 'microsoft:internet_information_services')),
			(_nuclei_item('microsoft-iis-version', ['tech', 'microsoft', 'iis'], extracted=['Microsoft-IIS/8.5']),
			 ('Microsoft IIS', '8.5', 'microsoft:internet_information_services')),
			(_nuclei_item('apache-detect', ['tech', 'apache'], extracted=['Apache/2.4.7 (Ubuntu)']),
			 ('Apache HTTP Server', '2.4.7', 'apache:http_server')),
			(_nuclei_item('ms-exchange-server', 'microsoft,exchange,tech,discovery', extracted=['15.1.2507']),
			 ('Microsoft Exchange Server', '15.1.2507', 'microsoft:exchange_server')),
			(_nuclei_item('weblogic-login', ['panel', 'oracle', 'weblogic'], extracted=['12.2.1.3.0'],
						  metadata={'vendor': 'oracle', 'product': 'weblogic_server'},
						  cpe='cpe:2.3:a:oracle:weblogic_server:*:*:*:*:-:*:*:*'),
			 ('Oracle WebLogic Server', '12.2.1.3.0', 'oracle:weblogic_server')),
			(_nuclei_item('wordpress-detect', ['tech', 'wordpress'], extracted=['6.8.6'],
						  metadata={'vendor': 'wordpress', 'product': 'wordpress'}),
			 ('WordPress', '6.8.6', 'wordpress:wordpress')),
			(_nuclei_item('openssh-detect', ['network', 'ssh', 'openssh', 'detect']),
			 ('OpenSSH', None, 'openbsd:openssh')),
			(_nuclei_item('php-detect', ['tech', 'php'], extracted=['8.5.8'], metadata={'vendor': 'php', 'product': 'php'}),
			 ('PHP', '8.5.8', 'php:php')),
		]
		for item, (product, version, key) in cases:
			with self.subTest(template=item['template-id'], matcher=item.get('matcher-name')):
				tech = self._convert(item)
				self.assertIsInstance(tech, Technology)
				self.assertEqual((tech.product, tech.version, tech.key), (product, version, key))

	def test_connector_version_is_not_the_tomcat_release(self):
		tech = Technology(match='127.0.0.1:8080', product='Apache Tomcat/Coyote JSP engine', version='1.1')
		self.assertEqual((tech.product, tech.version, tech.key), ('Apache Tomcat', None, 'apache:tomcat'))

	def test_product_from_extracted_banner(self):
		tech = self._convert(_nuclei_item('apache-detect', ['tech', 'apache'], extracted=['Apache-Coyote/1.1']))
		self.assertEqual((tech.product, tech.version, tech.key), ('Apache Tomcat', None, 'apache:tomcat'))
		tech = self._convert(_nuclei_item('apache-detect', ['tech', 'apache'], extracted=['Apache/2.4.58 (Unix) OpenSSL/3.0.2']))  # noqa: E501
		self.assertEqual((tech.product, tech.version, tech.key), ('Apache HTTP Server', '2.4.58', 'apache:http_server'))

	def test_plugin_is_its_own_product(self):
		tech = self._convert(_nuclei_item('wordpress-wp-file-manager', ['tech', 'wordpress', 'wp-plugin'], extracted=['8.0.4']))  # noqa: E501
		self.assertEqual((tech.product, tech.version), ('wordpress wp file manager', '8.0.4'))
		self.assertNotEqual(tech.key, 'wordpress:wordpress')

	def test_cpe_kept(self):
		tech = self._convert(_nuclei_item('weblogic-login', ['panel'], cpe='cpe:2.3:a:oracle:weblogic_server:*:*:*:*:-:*:*:*'))  # noqa: E501
		self.assertEqual(tech.extra_data['cpe'], ['cpe:2.3:a:oracle:weblogic_server:*:*:*:*:-:*:*:*'])

	def test_weaknesses_stay_tags_or_vulns(self):
		from secator.output_types import Tag, Vulnerability
		self.assertIs(self._convert(_nuclei_item('http-missing-security-headers', ['misconfig', 'headers'])), Tag)
		self.assertIs(self._convert(_nuclei_item('wordpress-readme-file', ['exposure', 'wordpress', 'vuln'],
												  metadata={'vendor': 'wordpress', 'product': 'wordpress'})), Tag)
		self.assertIs(self._convert(_nuclei_item('tls-version', ['ssl', 'tls'])), Tag)
		# a WAF signature and a stock page are not products
		self.assertIs(self._convert(_nuclei_item('waf-detect', ['waf', 'tech', 'misc'], matcher_name='nginxgeneric')), Tag)
		self.assertIs(self._convert(_nuclei_item('default-windows-server-page', ['tech', 'windows', 'iis'],
												  cpe='cpe:2.3:o:microsoft:windows_server_2003:*:*:*:*:*:*:*:*')), Tag)
		self.assertIs(self._convert(_nuclei_item('some-cve', ['cve', 'tech'], severity='high')), Vulnerability)


class TestUrlTechs(unittest.TestCase):

	def test_wappalyzer_and_server_header_strings(self):
		from secator.output_types import Url
		url = Url(url='http://scanme.nmap.org', tech=[
			'Apache HTTP Server:2.4.7', 'Apache/2.4.7 (Ubuntu)', 'jQuery UI:1.10.3', 'Nginx', 'Apache-Coyote/1.1'])  # noqa: E501
		got = [(t.product, t.version, t.key) for t in url.get_techs()]
		self.assertEqual(got, [
			('Apache HTTP Server', '2.4.7', 'apache:http_server'),
			('Apache HTTP Server', '2.4.7', 'apache:http_server'),
			('jQuery UI', '1.10.3', 'jquery:jquery_ui'),
			('nginx', None, 'f5:nginx'),
			('Apache Tomcat', None, 'apache:tomcat'),
		])


if __name__ == '__main__':
	unittest.main()
