import logging
import os
import unittest
import warnings
from time import sleep

from secsy.celery import app
from secsy.definitions import *
from secsy.output_types import Port, Vulnerability, Ip, Subdomain, Tag, Target, Url, UserAccount
from secsy.rich import console
from secsy.runners import Command
from secsy.utils import setup_logging
from secsy.utils_test import FIXTURES, META_OPTS, CommandOutputTester

INTEGRATION_DIR = os.path.dirname(os.path.abspath(__file__))
level = logging.DEBUG if DEBUG > 0 else logging.INFO
setup_logging(level)


INPUTS = {
    URL: f'http://localhost:3000/',
    HOST: 'localhost',
    USERNAME: 'ocervell',
    IP: '127.0.0.1',
    CIDR_RANGE: '192.168.1.0/24',
    'dalfox': 'http://testphp.vulnweb.com/listproducts.php?cat=123&artist=123&asdf=ff',
    'ffuf': 'http://localhost:3000/FUZZ',
    'gf': 'http://localhost:3000?q=test',
    'gau': 'https://danielmiessler.com/',
    'gospider': 'https://danielmiessler.com/',
    'grype': ROOT_FOLDER,
    'nuclei': 'http://localhost:3000/',
    'subfinder': 'api.github.com'
}

OUTPUTS = {
    'dirsearch': [
        Url(url='http://localhost:3000/.well-known/security.txt', status_code=200, content_type='text/plain', content_length=403, _source='dirsearch'),
    ],
    'dalfox': [
        Vulnerability(
            matched_at='http://testphp.vulnweb.com/listproducts.php',
            name=None,
            confidence='high',
            severity='high',
            cvss_score=0,
            tags=['CWE-79'],
            extracted_results={
                'inject_type': 'inHTML-URL',
                'poc_type': 'plain',
                'method': 'GET',
                'data': 'http://testphp.vulnweb.com/listproducts.php?artist=123&asdf=ff&cat=123%3C%2FScriPt%3E%3CsCripT+class%3Ddalfox%3Ealert%281%29%3C%2FsCriPt%3E',
                'param': 'cat',
                'payload': '</ScriPt><sCripT class=dalfox>alert(1)</sCriPt>',
                'evidence': ''
            },
            _source='dalfox'
        )
    ],
    'cariddi': [
        Url(url='http://localhost:3000/robots.txt', status_code=0, _source='cariddi'),
        Url(url='http://localhost:3000/main.js', status_code=0, _source='cariddi')
    ],
    'feroxbuster': [
        Url(
            url='http://localhost:3000/video',
            status_code=200,
            content_type='video/mp4',
            content_length=10075518,
            method='GET',
            _source='feroxbuster'
        ),
        Url(
            url='http://localhost:3000/ftp',
            status_code=200,
            content_type='text/html; charset=utf-8',
            content_length=11093,
            method='GET',
            _source='feroxbuster'
        )
    ],
    'ffuf': [
        Url(url='http://localhost:3000/api-docs', host='localhost:3000', status_code=200, title='', webserver='', tech=[], content_type='text/html; charset=utf-8', content_length=3103, method='GET', words=420, lines=81, _source='ffuf')
    ],
    'fping': [
        Ip(ip='127.0.0.1', alive=True, _source='fping')
    ],
    'gau': [
        Url(url='http://www.danielmiessler.com/wp-content/uploads/2010/03/self_discipline.jpeg', _source='gau')
    ],
    'gf': [
        Tag(name='xss', match='http://localhost:3000?q=test', _source='gf')
    ],
    'gospider': [
        Url(url='https://danielmiessler.com/technology/', status_code=200, content_length=48, _source='gospider')
    ],
    'grype': [
        Vulnerability(
            matched_at=ROOT_FOLDER,
            name='Navigation Remapping To Propagate Malicious Content',
            provider='cve.circl.lu',
            id='CVE-2022-23491',
            confidence='low',
            severity='unknown',
            cvss_score=0,
            tags=['ghsa'],
            extracted_results={
                'product': 'certifi',
                'version': '2022.12.07',
                'product_type': 'python',
                'ghsa_id': 'GHSA-43fp-rhv2-5gv8'
            },
            _source='grype',
        )
    ],
    'httpx': [
        Url(url='http://localhost:3000', status_code=200, title='OWASP Juice Shop', content_type='text/html', content_length=1987, method='GET', words=207, lines=30, _source='httpx')
    ],
    'katana': [
        Url(url='http://localhost:3000/vendor.js', host='localhost:3000', status_code=200, method='GET', _source='katana')
    ],
    'maigret': [
        UserAccount(site_name='GitHub', username='ocervell', url='https://github.com/ocervell', _source='maigret')
    ],
    'mapcidr': [
        Ip(ip='192.168.1.0', alive=False, _source='mapcidr'),
        Ip(ip='192.168.1.255', alive=False, _source='mapcidr')
    ],
    'msfconsole': [],
    'naabu': [
        Port(port=3000, host='localhost', ip='127.0.0.1', _source='naabu'),
        Port(port=8080, host='localhost', ip='127.0.0.1', _source='naabu'),
    ],
    'nmap': [
        Port(port=3000, host='localhost', ip='127.0.0.1', service_name='ppp', _source='nmap'),
        Port(port=8080, host='localhost', ip='127.0.0.1', service_name='nagios-nsca',  _source='nmap'),
        Vulnerability(
            matched_at='localhost:8080',
            name='OS Command Injection',
            provider='cve.circl.lu',
            id='CVE-2013-4781',
            severity='critical',
            confidence='low',
            cvss_score=10.0,
            _source='nmap'
        )
    ],
    'nuclei': [
        Vulnerability(
            matched_at='http://localhost:3000/metrics',
            name='Prometheus Metrics - Detect',
            confidence='high',
            severity='medium',
            cvss_score=5.3,
            tags=['exposure', 'prometheus', 'hackerone', 'config'],
            extracted_results={'data': []},
            description='Prometheus metrics page was detected.',
            _source='nuclei')
    ],
    'subfinder': [
        Subdomain(host='virusscan.api.github.com', domain='api.github.com', _source='subfinder')
    ],
}


class TestCommand(unittest.TestCase, CommandOutputTester):
    def setUp(self):
        warnings.simplefilter('ignore', category=ResourceWarning)
        warnings.simplefilter('ignore', category=DeprecationWarning)
        Command.run_command(
            f'sh {INTEGRATION_DIR}/setup.sh',
            cwd=INTEGRATION_DIR
        )
        # sleep(10)

    def tearDown(self):
        pass
        # Command.run_command(
        #     f'sh {INTEGRATION_DIR}/teardown.sh',
        #     cwd=INTEGRATION_DIR
        # )

    def test_all_commands(self):
        opts = META_OPTS.copy()
        opts['print_item'] = DEBUG > 1
        opts['print_cmd'] = DEBUG > 0
        opts['print_line'] = DEBUG > 1
        opts['table'] = DEBUG > 0
        del opts['nmap.output_path']
        del opts['maigret.output_path']
        opts['ffuf.fs'] = 1987
        opts['match_codes'] = '200'
        opts['maigret.site'] = 'github'
        for cls, _ in FIXTURES.items():
            with self.subTest(name=cls.__name__):
                console.print(f'Testing {cls.__name__} ...')
                input = INPUTS[cls.__name__] if cls.__name__ in INPUTS else INPUTS[cls.input_type]
                outputs = OUTPUTS[cls.__name__] if cls.__name__ in OUTPUTS else []
                command = cls(input, **opts)
                results = command.run()

                # Check return code
                if not command.ignore_return_code:
                    self.assertEqual(command.return_code, 0)

                if not results:
                    console.print(
                        f'No results from {cls.__name__} ! Skipping item check.')

                # Test result types
                self._test_command_output(
                    results,
                    expected_output_types=cls.output_types,
                    expected_results=outputs)
 