from secsy.definitions import ROOT_FOLDER
from secsy.output_types import (Port, Subdomain, Tag, Url, UserAccount,
                                Vulnerability, Ip)

OUTPUTS = {
    'dirsearch': [
        Url(
            url='http://localhost:3000/.well-known/security.txt',
            status_code=200,
            content_type='text/plain',
            content_length=403,
            _source='dirsearch'
        ),
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
        ),
    ],
    'cariddi': [
        Url(url='http://localhost:3000/robots.txt', status_code=0, _source='cariddi'),
        Url(url='http://localhost:3000/main.js', status_code=0, _source='cariddi')
    ],
    'feroxbuster': [
        Url(
            url='http://localhost:3000/video/',
            status_code=200,
            content_type='video/mp4',
            content_length=18331192,
            words=264108,
            lines=49061,
            method='GET',
            _source='feroxbuster'
        ),
        Url(
            url='http://localhost:3000/ftp/',
            status_code=200,
            content_type='text/html; charset=utf-8',
            content_length=11097,
            method='GET',
            _source='feroxbuster'
        )
    ],
    'ffuf': [
        Url(
            url='http://localhost:3000/api-docs/',
            host='localhost:3000',
            status_code=200,
            tech=[],
            content_type='text/html; charset=utf-8',
            content_length=3103,
            method='GET',
            words=420,
            lines=81,
            _source='ffuf'
        )
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
        Url(
            url='http://localhost:3000',
            status_code=200,
            title='OWASP Juice Shop',
            content_type='text/html',
            content_length=1987,
            method='GET',
            words=207,
            lines=30,
            _source='httpx'
        )
    ],
    'katana': [
        Url(
            url='http://localhost:3000/vendor.js',
            host='localhost:3000',
            status_code=200,
            method='GET',
            _source='katana'
        )
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