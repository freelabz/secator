import json
import os
import unittest


class TestShodanConfig(unittest.TestCase):
    def test_addon_defaults(self):
        from secator.config import CONFIG
        self.assertFalse(CONFIG.addons.shodan.enabled)
        self.assertEqual(CONFIG.addons.shodan.api_key, '')


def _load_fixture():
    path = os.path.join(os.path.dirname(__file__), '..', 'fixtures', 'shodan_output.json')
    with open(path) as f:
        return json.load(f)


class TestShodanMapping(unittest.TestCase):
    def _run(self):
        from secator.output_types import Ip, Subdomain, Port, Technology, Vulnerability, Tag
        from secator.tasks.shodan import shodan
        task = shodan.__new__(shodan)
        return list(task._map_host(_load_fixture(), '10.0.0.1', 'host1.example.com'))

    def test_emits_ip(self):
        from secator.output_types import Ip
        ips = [r for r in self._run() if isinstance(r, Ip)]
        self.assertEqual(len(ips), 1)
        self.assertEqual(ips[0].ip, '10.0.0.1')
        self.assertTrue(ips[0].alive)
        self.assertEqual(ips[0].extra_data.get('org'), 'Example Org')

    def test_emits_subdomains_deduped(self):
        from secator.output_types import Subdomain
        subs = [r for r in self._run() if isinstance(r, Subdomain)]
        hosts = sorted(s.host for s in subs)
        self.assertEqual(hosts, ['example.com', 'host1.example.com', 'www.example.com'])

    def test_emits_one_port_per_banner(self):
        from secator.output_types import Port
        ports = sorted(p.port for p in self._run() if isinstance(p, Port))
        self.assertEqual(ports, [80, 443])

    def test_ports_are_low_confidence(self):
        from secator.output_types import Port
        for p in [r for r in self._run() if isinstance(r, Port)]:
            self.assertEqual(p.confidence, 'low')

    def test_emits_technology_with_match_hostport(self):
        from secator.output_types import Technology
        techs = [r for r in self._run() if isinstance(r, Technology)]
        self.assertTrue(any(t.product == 'Apache httpd' and t.match == '10.0.0.1:80' for t in techs))

    def test_emits_vulns_low_confidence(self):
        from secator.output_types import Vulnerability
        vulns = [r for r in self._run() if isinstance(r, Vulnerability)]
        names = {v.name for v in vulns}
        self.assertIn('CVE-2021-40438', names)   # top-level
        self.assertIn('CVE-2021-41773', names)   # per-banner
        for v in vulns:
            self.assertEqual(v.confidence, 'low')
        banner_vuln = next(v for v in vulns if v.name == 'CVE-2021-41773')
        self.assertEqual(banner_vuln.cvss_score, 7.5)
        self.assertEqual(banner_vuln.matched_at, '10.0.0.1:80')

    def test_emits_tags_for_metadata(self):
        from secator.output_types import Tag
        tags = {t.name for t in self._run() if isinstance(t, Tag)}
        self.assertEqual(tags, {'shodan_org', 'shodan_isp', 'shodan_asn', 'shodan_os'})
