import json
import os
import unittest
import unittest.mock


def _load_dns_fixture():
    path = os.path.join(os.path.dirname(__file__), '..', 'fixtures', 'shodan_dns_output.json')
    with open(path) as f:
        return json.load(f)


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


class TestShodanErrorPaths(unittest.TestCase):
    """Test yielder() error branches: missing key, no-data warning, generic API error."""

    def _make_task(self, **run_opts):
        from secator.tasks.shodan import shodan
        task = shodan.__new__(shodan)
        task.run_opts = run_opts
        task.inputs = ['10.0.0.1']
        return task

    def test_missing_api_key_yields_single_error(self):
        """No api_key opt, no config key, no env var → exactly one Error, no findings."""
        from secator.output_types import Error
        task = self._make_task(api_key='')
        mock_cfg = unittest.mock.MagicMock()
        mock_cfg.addons.shodan.api_key = ''
        env_without_key = {k: v for k, v in os.environ.items() if k != 'SHODAN_API_KEY'}
        with unittest.mock.patch('secator.tasks.shodan.CONFIG', mock_cfg), \
             unittest.mock.patch.dict(os.environ, env_without_key, clear=True):
            results = list(task.yielder())
        errors = [r for r in results if isinstance(r, Error)]
        self.assertEqual(len(results), 1)
        self.assertEqual(len(errors), 1)
        self.assertIn('API key', errors[0].message)

    def test_no_information_available_yields_warning_not_error(self):
        """shodan.APIError('No information available...') → one Warning, zero Errors."""
        import shodan as shodan_sdk
        from secator.output_types import Error, Warning
        task = self._make_task(api_key='testkey')
        mock_api = unittest.mock.MagicMock()
        mock_api.host.side_effect = shodan_sdk.APIError('No information available for that IP.')
        with unittest.mock.patch('shodan.Shodan', return_value=mock_api):
            results = list(task.yielder())
        warnings = [r for r in results if isinstance(r, Warning)]
        errors = [r for r in results if isinstance(r, Error)]
        self.assertEqual(len(warnings), 1)
        self.assertEqual(len(errors), 0)

    def test_generic_api_error_yields_error(self):
        """Non-'No information' shodan.APIError → one Error containing the message."""
        import shodan as shodan_sdk
        from secator.output_types import Error, Warning
        task = self._make_task(api_key='testkey')
        mock_api = unittest.mock.MagicMock()
        mock_api.host.side_effect = shodan_sdk.APIError('Invalid API key')
        with unittest.mock.patch('shodan.Shodan', return_value=mock_api):
            results = list(task.yielder())
        errors = [r for r in results if isinstance(r, Error)]
        warnings = [r for r in results if isinstance(r, Warning)]
        self.assertEqual(len(errors), 1)
        self.assertEqual(len(warnings), 0)
        self.assertIn('Invalid API key', errors[0].message)


class TestShodanDns(unittest.TestCase):
    def _run(self, record_types=None):
        from secator.tasks.shodan import shodan
        task = shodan.__new__(shodan)
        types = record_types or ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']
        return list(task._map_dns('example.com', _load_dns_fixture(), types))

    def test_emits_record_per_type(self):
        from secator.output_types import Record
        recs = [r for r in self._run() if isinstance(r, Record)]
        types = sorted({r.type for r in recs})
        self.assertEqual(types, ['A', 'AAAA', 'MX', 'TXT'])
        a = next(r for r in recs if r.type == 'A' and r.name == 'www.example.com')
        self.assertEqual(a.host, 'example.com')
        self.assertEqual(a.extra_data.get('value'), '93.184.216.34')

    def test_ip_only_for_public_a_aaaa(self):
        from secator.output_types import Ip
        ips = sorted({i.ip for i in self._run() if isinstance(i, Ip)})
        # public A + AAAA only; the 10.0.0.5 private A is excluded
        self.assertEqual(ips, ['2606:2800:220:1:248:1893:25c8:1946', '93.184.216.34'])

    def test_emits_subdomains_from_list(self):
        from secator.output_types import Subdomain
        subs = sorted({s.host for s in self._run() if isinstance(s, Subdomain)})
        self.assertEqual(subs, ['mail.example.com', 'www.example.com'])

    def test_record_types_filter(self):
        from secator.output_types import Record
        recs = [r for r in self._run(record_types=['MX']) if isinstance(r, Record)]
        self.assertEqual({r.type for r in recs}, {'MX'})
