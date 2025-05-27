from secator.definitions import ROOT_FOLDER
from secator.output_types import (Ip, Port, Subdomain, Tag, Url, UserAccount,
                                Vulnerability, Record, Certificate)


OUTPUTS_CHECKS = {
    'output_types': {
        Url: {
            'checks': [
                {
                    'info': 'should have request header "Hello"',
                    'error': 'Request header "Hello" not present in URL object',
                    'function': lambda item: 'Hello' in item.request_headers,
                },
                {
                    'info': 'should have request header "Hello" set to "World"',
                    'error': 'Request header "Hello" not set to "World"',
                    'function': lambda item: item.request_headers['Hello'] == 'World',
                }
            ],
            'runner': '^(?!gau$).*',
        }
    },
    # 'runner': {
    #     Command: {

    #     }
    # }
}

OUTPUTS_TASKS = {
    'arjun': [
        Url(
            url='http://testphp.vulnweb.com/hpp?pp=FUZZ',
            _source='arjun'
        )
    ],
	'bup': [
        Url(
            url='http://localhost:3000/ftp/coupons_2013.md.bak',
            status_code=403,
            content_length=164,
            content_type='text/html',
            method='GET',
            _source='bup'
        ),
        Url(
            url='http://localhost:3000/ftp/coupons_2013.md.bak',
            status_code=405,
            method='SEARCH',
            _source='bup'
        )
	],
    'cariddi': [
        Url(
            url='http://localhost:3000/robots.txt',
            status_code=200,
            content_length=28,
            content_type='text/plain',
            method='GET',
            words=4,
            lines=2,
            _source='cariddi'
        ),
        Url(
            url='http://localhost:3000/main.js',
            status_code=200,
            content_type='application/javascript',
            method='GET',
            words=6048,
            lines=1,
            _source='cariddi'
        )
    ],
    'dirsearch': [
        Url(
            url='http://localhost:3000/.well-known/security.txt',
            status_code=200,
            content_type='text/plain',
            content_length=403,
            _source='dirsearch'
        ),
    ],
    'dnsx': [
        Record(
            name= "dyna.wikimedia.org",
            type= "CNAME",
            host= "be.wikipedia.org",
            _source= "dnsx"
		),
        Record(
            name= "be.wikipedia.org",
            type= "AXFR",
            host= "be.wikipedia.org",
            _source= "dnsx"
		),
        Record(
            name= "wikimedia.org",
            type= "SOA",
            host= "be.wikipedia.org",
            _source= "dnsx"
		),
        # Record(
        #     name='digicert.com',
        #     type='CAA',
        #     host='wikipedia.org',
        #     _source='dnsx'
		# ),
        # Record(
        #     name='v=spf1 include:_cidrs.wikimedia.org ~all',
        #     type='TXT',
        #     host='wikipedia.org',
        #     _source='dnsx'
		# ),
        Subdomain(host="be.wikipedia.org", domain="wikipedia.org", _source="dnsx"),
        Subdomain(host="commons.wikipedia.org", domain="wikipedia.org", _source="dnsx"),
		# Subdomain(host="de.wikipedia.org", domain="wikipedia.org", _source="dnsx"),
	],
    'dalfox': [
        Vulnerability(
            matched_at='http://testphp.vulnweb.com/listproducts.php',
            name='Verified XSS',
            confidence='high',
            severity='high',
            cvss_score=0,
            tags=['CWE-79'],
            extra_data={
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
            content_length=3106,
            method='GET',
            words=422,
            lines=82,
            _source='ffuf'
        )
    ],
    'fping': [
        Ip(ip='127.0.0.1', alive=True, _source='fping')
    ],
    'gau': [
        Url(url='http://testphp.vulnweb.com/.idea/.name', _source='gau')
    ],
    'gf': [
        Tag(name='xss pattern', match='http://localhost:3000?q=test', _source='gf')
    ],
    'gitleaks': [
        # TODO: allow to test equality for this (dynamic path based on runner)
        # Tag(name='aws-access-token', match='/path/to/file.py:216', _source='gitleaks')
    ],
    'gospider': [
        Url(url='https://danielmiessler.com/predictions/', status_code=200, content_length=23, _source='gospider')
    ],
    'grype': [
		Vulnerability(
			name='CVE-2024-24790',
			provider='grype',
			id='CVE-2024-24790',
			matched_at='redis:7.4.1',
			ip='',
			confidence='medium',
			severity='critical',
			cvss_score=-1,
			tags=[],
			_source='grype',
		)
    ],
    'h8mail': [
        UserAccount(
            username='test',
            email='test@test.com',
            _source='h8mail',
        )
    ],
    'httpx': [
        Url(
            url='http://localhost:3000',
            status_code=200,
            title='OWASP Juice Shop',
            content_type='text/html',
            content_length=3748,
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
        UserAccount(
			site_name='GitHubGist',
			username='ocervell',
			url='https://gist.github.com/ocervell',
			_source='maigret'
		)
    ],
    'mapcidr': [
        Ip(ip='192.168.1.0', alive=False, _source='mapcidr'),
        Ip(ip='192.168.1.255', alive=False, _source='mapcidr')
    ],
    'msfconsole': [],
    'naabu': [
        Port(port=3000, ip='127.0.0.1', state='open', _source='naabu'),
        Port(port=8080, ip='127.0.0.1', state='open', _source='naabu'),
    ],
    'nmap': [
        Port(port=3000, ip='127.0.0.1', state='open', service_name='ppp', _source='nmap'),
        Port(port=8080, ip='127.0.0.1', state='open', service_name='nagios nsca', _source='nmap'),
    ],
    'nuclei': [
        Vulnerability(
            matched_at='http://localhost:3000/metrics',
			ip='127.0.0.1',
            name='prometheus-metrics',
            confidence='high',
            severity='medium',
            cvss_score=5.3,
            tags=['exposure', 'prometheus', 'hackerone', 'config'],
            extra_data={'data': []},
            description='Prometheus metrics page was detected.',
            _source='nuclei')
    ],
    'subfinder': [
        Subdomain(host='virusscan.api.github.com', domain='api.github.com', _source='subfinder')
    ],
    'trivy': [
        Vulnerability(
            matched_at='https://github.com/blacklanternsecurity/bbot',
            provider='ghsa',
            name='CVE-2024-8775',
            id='CVE-2024-8775',
            confidence='high',
            severity='high',
            cvss_score=5.5,
            _source='trivy'
        ),
    ],
    'wafw00f': [
        Tag(
            name='Envoy WAF',
            match='https://netflix.com',
            _source='wafw00f')
    ],
    'testssl': [
        Certificate(host='free.fr', fingerprint_sha256='EBC7C611F9A4161B123D3DF03E852BD69DFFDC447D223AE9478D434D55DFAD9B', _source='testssl')
    ],
    'wpscan': [
        Tag(
            name='Wordpress theme - twentytwentyfive 1.2',
            match='http://localhost:8000/',
            _source='wpscan'),
        Vulnerability(
			matched_at='http://localhost:8000/',
			ip='127.0.0.1',
			name='Headers',
			confidence='high',
			severity='info',
			cvss_score=0,
			tags=['headers'],
			_source='wpscan'),
        Vulnerability(
			matched_at='http://localhost:8000/xmlrpc.php',
			ip='127.0.0.1',
			name='XML-RPC seems to be enabled',
			confidence='high',
			severity='info',
			cvss_score=0,
			tags=['xmlrpc'],
			_source='wpscan'),
        Vulnerability(
			matched_at='http://localhost:8000/readme.html',
			ip='127.0.0.1',
			name='WordPress readme found',
			confidence='high',
			severity='info',
			cvss_score=0,
			tags=['readme'],
			_source='wpscan'),
	]
}

OUTPUTS_WORKFLOWS = {
    'cidr_recon': [
    	Ip(ip='127.0.0.1', host='', alive=True, _source='fping', _type='ip')
	],
    'code_scan': [
    	Vulnerability(matched_at=ROOT_FOLDER, ip='127.0.0.1', name='CVE-2023-28859', provider='cve.circl.lu', id='CVE-2023-28859', confidence='low', severity='unknown', cvss_score=0, tags=['ghsa'], extra_data={'product': 'redis', 'version': '4.5.4', 'product_type': 'python', 'ghsa_id': 'GHSA-8fww-64cx-x8p5'}, description='redis-py before 4.4.4 and 4.5.x before 4.5.4 leaves a connection open after canceling an async Redis command at an inopportune time, and can send response data to the client of an unrelated request. (This could, for example, happen for a non-pipeline operation.) NOTE: the solutions for  address data leakage across AsyncIO connections in general.', references=['https://cve.circl.lu/cve/CVE-2023-28859', 'https://github.com/redis/redis-py/pull/2641', 'https://github.com/redis/redis-py/issues/2665', 'https://github.com/redis/redis-py/releases/tag/v4.4.4', 'https://github.com/redis/redis-py/releases/tag/v4.5.4', 'https://github.com/redis/redis-py/pull/2666', 'https://cve.circl.lu/cve/CVE-2023-28859'], reference='https://cve.circl.lu/cve/CVE-2023-28859', confidence_nb=3, severity_nb=5, _source='grype', _type='vulnerability'),
		Vulnerability(matched_at=ROOT_FOLDER, ip='127.0.0.1', name='CVE-2023-28858', provider='cve.circl.lu', id='CVE-2023-28858', confidence='low', severity='unknown', cvss_score=0, tags=['ghsa'], extra_data={'product': 'redis', 'version': '4.5.3', 'product_type': 'python', 'ghsa_id': 'GHSA-24wv-mv5m-xv4h'}, description='redis-py before 4.5.3 leaves a connection open after canceling an async Redis command at an inopportune time, and can send response data to the client of an unrelated request in an off-by-one manner. NOTE: this CVE Record was initially created in response to reports about ChatGPT, and 4.3.6, 4.4.3, and 4.5.3 were released (changing the behavior for pipeline operations); however, please see CVE-2023-28859 about addressing data leakage across AsyncIO connections in general.', references=['https://cve.circl.lu/cve/CVE-2023-28858', 'https://github.com/redis/redis-py/compare/v4.3.5...v4.3.6', 'https://github.com/redis/redis-py/pull/2641', 'https://openai.com/blog/march-20-chatgpt-outage', 'https://github.com/redis/redis-py/issues/2624', 'https://github.com/redis/redis-py/compare/v4.4.2...v4.4.3', 'https://github.com/redis/redis-py/compare/v4.5.2...v4.5.3', 'https://cve.circl.lu/cve/CVE-2023-28858'], reference='https://cve.circl.lu/cve/CVE-2023-28858', confidence_nb=3, severity_nb=5, _source='grype', _type='vulnerability'),
		Vulnerability(matched_at=ROOT_FOLDER, ip='127.0.0.1', name='Owner Footprinting', provider='cve.circl.lu', severity='medium', tags=['ghsa'], id='CVE-2023-43804', extra_data={'product': 'urllib3', 'product_type': 'python', 'version': '2.0.5', 'version_fixed': '2.0.6', 'ghsa_id': 'GHSA-v845-jxx5-vc9f'}, _source='grype'),
		Vulnerability(matched_at=ROOT_FOLDER, ip='127.0.0.1', name='Navigation Remapping To Propagate Malicious Content', provider='cve.circl.lu', id='CVE-2022-23491', confidence='low', severity='unknown', cvss_score=0, tags=['ghsa'], extra_data={'product': 'certifi', 'version': '2022.12.07', 'product_type': 'python', 'ghsa_id': 'GHSA-43fp-rhv2-5gv8'}, description='Certifi is a curated collection of Root Certificates for validating the trustworthiness of SSL certificates while verifying the identity of TLS hosts. Certifi 2022.12.07 removes root certificates from "TrustCor" from the root store. These are in the process of being removed from Mozilla\'s trust store. TrustCor\'s root certificates are being removed pursuant to an investigation prompted by media reporting that TrustCor\'s ownership also operated a business that produced spyware. Conclusions of Mozilla\'s investigation can be found in the linked google group discussion.', references=['https://cve.circl.lu/cve/CVE-2022-23491', 'https://groups.google.com/a/mozilla.org/g/dev-security-policy/c/oxX69KFvsm4/m/yLohoVqtCgAJ', 'https://github.com/certifi/python-certifi/security/advisories/GHSA-43fp-rhv2-5gv8', 'https://cve.circl.lu/cve/CVE-2022-23491'], reference='https://cve.circl.lu/cve/CVE-2022-23491', confidence_nb=3, severity_nb=5, _source='grype', _type='vulnerability')
	],
    'host_recon': [
		Port(port=8080, host='localhost', ip='127.0.0.1', state='open', service_name='nagios nsca', cpes=[], extra_data={'name': 'nagios-nsca', 'product': 'nagios nsca', 'method': 'probed', 'conf': '10', 'nmap_script': 'vulscan'}, _source='nmap', _type='port'),
		Port(port=3000, host='localhost', ip='127.0.0.1', state='open', service_name='ppp', cpes=[], extra_data={'name': 'ppp', 'conf': '3', 'nmap_script': 'fingerprint-strings'}, _source='nmap', _type='port'),
		# Vulnerability(matched_at='http://localhost:8080/', ip='127.0.0.1', name='Spring Boot - Remote Code Execution (Apache Log4j)', provider='', id='cve-2021-44228', confidence='high', severity='critical', cvss_score=10, tags=['cve', 'cve2021', 'springboot', 'rce', 'oast', 'log4j', 'kev'], extra_data={'data': ['192.221.154.139', 'f978d7010c8a']}, description='Spring Boot is susceptible to remote code execution via Apache Log4j.', references=['https://logging.apache.org/log4j/2.x/security.html', 'https://www.lunasec.io/docs/blog/log4j-zero-day/', 'https://github.com/twseptian/spring-boot-log4j-cve-2021-44228-docker-lab', 'https://nvd.nist.gov/vuln/detail/cve-2021-44228'], reference='https://logging.apache.org/log4j/2.x/security.html', confidence_nb=1, severity_nb=0, _source='nuclei', _type='vulnerability'),
		Vulnerability(matched_at='http://localhost:3000', ip='127.0.0.1', name='fingerprinthub-web-fingerprints:qm-system', provider='', id='', confidence='high', severity='info', cvss_score=0, tags=['tech'], extra_data={'data': []}, description='FingerprintHub Technology Fingerprint tests run in nuclei.', references=['https://github.com/0x727/fingerprinthub'], reference='https://github.com/0x727/fingerprinthub', confidence_nb=1, severity_nb=4, _source='nuclei', _type='vulnerability'),
		Vulnerability(matched_at='http://localhost:3000/.well-known/security.txt', ip='127.0.0.1', name='security-txt', provider='', id='', confidence='high', severity='info', cvss_score=0, tags=['misc', 'generic'], extra_data={'data': [' mailto:donotreply@owasp-juice.shop']}, description='The website defines a security policy.', references=[], reference='', confidence_nb=1, severity_nb=4, _source='nuclei', _type='vulnerability'),
		Vulnerability(matched_at='http://localhost:3000/metrics', ip='127.0.0.1', name='prometheus-metrics', provider='', id='', confidence='high', severity='medium', cvss_score=5.3, tags=['exposure', 'prometheus', 'hackerone', 'config'], extra_data={'data': []}, description='Prometheus metrics page was detected.', references=['https://github.com/prometheus/prometheus', 'https://hackerone.com/reports/1026196'], reference='https://github.com/prometheus/prometheus', confidence_nb=1, severity_nb=2, _source='nuclei', _type='vulnerability'),
		Vulnerability(matched_at='http://localhost:3000/api-docs/swagger.json', ip='127.0.0.1', name='swagger-api', provider='', id='', confidence='high', severity='info', cvss_score=0, tags=['exposure', 'api', 'swagger'], extra_data={'data': []}, description='Public Swagger API was detected.', references=['https://swagger.io/'], reference='https://swagger.io/', confidence_nb=1, severity_nb=4, _source='nuclei', _type='vulnerability'),
		Url(url='http://localhost:8080', host='127.0.0.1', status_code=400, title='', webserver='', tech=[], content_type='application/json', content_length=91, time=0.00341461, method='GET', words=2, lines=1, _source='httpx', _type='url'),
		Url(url='http://localhost:3000', host='127.0.0.1', status_code=200, title='OWASP Juice Shop', webserver='', tech=[], content_type='text/html', content_length=1987, time=0.00350711, method='GET', words=207, lines=30, _source='httpx', _type='url')
	],
    'subdomain_recon': [
    	Subdomain(host='virusscan.api.github.com', domain='api.github.com', sources=['alienvault'], _source='subfinder', _type='subdomain'),
        Subdomain(host='virus.api.github.com', domain='api.github.com', sources=['alienvault'], _source='subfinder', _type='subdomain'),
        Vulnerability(matched_at='virusscan.api.github.com', name='caa-fingerprint', provider='', id='', confidence='high', severity='info', cvss_score=0, tags=['dns', 'caa'], extra_data={'data': ['digicert.com', 'letsencrypt.org']}, description='A CAA record was discovered. A CAA record is used to specify which certificate authorities (CAs) are allowed to issue certificates for a domain.', references=['https://support.dnsimple.com/articles/caa-record/#whats-a-caa-record'], reference='https://support.dnsimple.com/articles/caa-record/#whats-a-caa-record', confidence_nb=1, severity_nb=4, _source='nuclei', _type='vulnerability'),
		Vulnerability(matched_at='virusscan.api.github.com', name='cname-fingerprint', provider='', id='', confidence='high', severity='info', cvss_score=0, tags=['dns', 'cname'], extra_data={'data': ['github.github.io.']}, description='A CNAME DNS record was discovered.', references=['https://www.theregister.com/2021/02/24/dns_cname_tracking/', 'https://www.ionos.com/digitalguide/hosting/technical-matters/cname-record/'], reference='https://www.theregister.com/2021/02/24/dns_cname_tracking/', confidence_nb=1, severity_nb=4, _source='nuclei', _type='vulnerability'),
		Vulnerability(matched_at='virus.api.github.com', name='caa-fingerprint', provider='', id='', confidence='high', severity='info', cvss_score=0, tags=['dns', 'caa'], extra_data={'data': ['digicert.com', 'letsencrypt.org']}, description='A CAA record was discovered. A CAA record is used to specify which certificate authorities (CAs) are allowed to issue certificates for a domain.', references=['https://support.dnsimple.com/articles/caa-record/#whats-a-caa-record'], reference='https://support.dnsimple.com/articles/caa-record/#whats-a-caa-record', confidence_nb=1, severity_nb=4, _source='nuclei', _type='vulnerability'),
        Vulnerability(matched_at='virus.api.github.com', name='cname-fingerprint', provider='', id='', confidence='high', severity='info', cvss_score=0, tags=['dns', 'cname'], extra_data={'data': ['github.github.io.']}, description='A CNAME DNS record was discovered.', references=['https://www.theregister.com/2021/02/24/dns_cname_tracking/', 'https://www.ionos.com/digitalguide/hosting/technical-matters/cname-record/'], reference='https://www.theregister.com/2021/02/24/dns_cname_tracking/', confidence_nb=1, severity_nb=4, _source='nuclei', _type='vulnerability'),
        Url(url='https://virus.api.github.com', host='185.199.108.153', status_code=404, title='Site not found · GitHub Pages', webserver='GitHub.com', tech=['Fastly', 'GitHub Pages', 'Varnish'], content_type='text/html', content_length=9115, time=0.055734349, method='GET', words=641, lines=80, _source='httpx', _type='url'),
	],
    'user_hunt': [
    	UserAccount(site_name='Docker Hub', username='ocervell', url='https://hub.docker.com/u/ocervell/', _source='maigret', _type='user_account'),
        UserAccount(site_name='PyPi', username='ocervell', url='https://pypi.org/user/ocervell', _source='maigret', _type='user_account'),
        UserAccount(site_name='GitHub', username='ocervell', url='https://github.com/ocervell', _source='maigret', _type='user_account'),
	],
    'url_nuclei': [
    	Vulnerability(matched_at='http://localhost:3000/metrics', ip='127.0.0.1', name='prometheus-metrics', provider='', id='', confidence='high', severity='medium', cvss_score=5.3, tags=['exposure', 'prometheus', 'hackerone', 'config'], extra_data={'data': []}, description='Prometheus metrics page was detected.', references=['https://github.com/prometheus/prometheus', 'https://hackerone.com/reports/1026196'], reference='https://github.com/prometheus/prometheus', confidence_nb=1, severity_nb=2, _source='nuclei', _type='vulnerability'),
		Vulnerability(matched_at='http://localhost:3000/metrics', ip='127.0.0.1', name='kubelet-metrics', provider='', id='', confidence='high', severity='info', cvss_score=0, tags=['tech', 'k8s', 'kubernetes', 'devops', 'kubelet'], extra_data={'data': []}, description='Scans for kubelet metrics', references=[], reference='', confidence_nb=1, severity_nb=4, _source='nuclei', _type='vulnerability'),
        Vulnerability(matched_at='http://localhost:3000/api-docs/swagger.json', ip='127.0.0.1', name='swagger-api', provider='', id='', confidence='high', severity='info', cvss_score=0, tags=['exposure', 'api', 'swagger'], extra_data={'data': []}, description='Public Swagger API was detected.', references=['https://swagger.io/'], reference='https://swagger.io/', confidence_nb=1, severity_nb=4, _source='nuclei', _type='vulnerability'),
		# Vulnerability(matched_at='http://localhost:8080/', ip='127.0.0.1', name='Spring Boot - Remote Code Execution (Apache Log4j)', provider='', id='cve-2021-44228', confidence='high', severity='critical', cvss_score=10, tags=['cve', 'cve2021', 'springboot', 'rce', 'oast', 'log4j', 'kev'], extra_data={'data': ['192.221.154.139', 'f978d7010c8a']}, description='Spring Boot is susceptible to remote code execution via Apache Log4j.', references=['https://logging.apache.org/log4j/2.x/security.html', 'https://www.lunasec.io/docs/blog/log4j-zero-day/', 'https://github.com/twseptian/spring-boot-log4j-cve-2021-44228-docker-lab', 'https://nvd.nist.gov/vuln/detail/cve-2021-44228'], reference='https://logging.apache.org/log4j/2.x/security.html', confidence_nb=1, severity_nb=0, _source='nuclei', _type='vulnerability'),
	],
    'url_crawl': [
		Url(url='http://localhost:3000', host='127.0.0.1', status_code=200, title='OWASP Juice Shop', webserver='', tech=[], content_type='text/html', content_length=1987, time=0.031154163000000002, method='GET', words=207, lines=30, _source='httpx', _type='url'),
		Url(url='http://localhost:3000/runtime.js', host='127.0.0.1', status_code=200, title='', webserver='', tech=[], content_type='application/javascript', content_length=3210, time=0.024072803, method='GET', words=63, lines=1, _source='httpx', _type='url'),
		Url(url='http://localhost:3000/main.js', host='127.0.0.1', status_code=200, title='', webserver='', tech=[], content_type='application/javascript', content_length=399134, time=0.075288438, method='GET', words=6165, lines=1, _source='httpx', _type='url'),
		Url(url='http://localhost:3000/polyfills.js', host='127.0.0.1', status_code=200, title='', webserver='', tech=[], content_type='application/javascript', content_length=54475, time=0.046900798, method='GET', words=1213, lines=1, _source='httpx', _type='url'),
		Url(url='http://localhost:3000/robots.txt', host='127.0.0.1', status_code=200, title='', webserver='', tech=[], content_type='text/plain', content_length=28, time=0.004258536, method='GET', words=3, lines=2, _source='httpx', _type='url'),
		Url(url='http://localhost:3000/styles.css', host='127.0.0.1', status_code=200, title='', webserver='', tech=[], content_type='text/css', content_length=609068, time=0.129273694, method='GET', words=14024, lines=31, _source='httpx', _type='url'),
		Url(url='http://localhost:3000/sitemap.xml', host='127.0.0.1', status_code=200, title='OWASP Juice Shop', webserver='', tech=[], content_type='text/html', content_length=1987, time=0.031110464, method='GET', words=207, lines=30, _source='httpx', _type='url'),
		Url(url='http://localhost:3000/assets/public/favicon_js.ico', host='127.0.0.1', status_code=200, title='', webserver='', tech=[], content_type='image/x-icon', content_length=15086, time=0.030026154, method='GET', words=16, lines=6, _source='httpx', _type='url'),
	],
	'url_fuzz': [
		Url(url='http://localhost:3000/ftp', host='127.0.0.1', status_code=200, title='listing directory /ftp', webserver='', tech=[], content_type='text/html', content_length=11082, time=0.39357221, method='GET', words=1558, lines=357, _source='httpx', _type='url'),
		Url(url='http://localhost:3000/robots.txt', host='127.0.0.1', status_code=200, title='', webserver='', tech=[], content_type='text/plain', content_length=28, time=0.161848739, method='GET', words=3, lines=2, _source='httpx', _type='url'),
		Url(url='http://localhost:3000/snippets', host='127.0.0.1', status_code=200, title='', webserver='', tech=[], content_type='application/json', content_length=707, time=0.18883662799999998, method='GET', words=1, lines=1, _source='httpx', _type='url'),
		Url(url='http://localhost:3000/video', host='127.0.0.1', status_code=200, title='', webserver='', tech=[], content_type='video/mp4', content_length=10075518, time=2.432185494, method='GET', words=50020, lines=49061, _source='httpx', _type='url'),
	],
    'url_vuln': [
		Tag(name='xss pattern', match='https://www.hahwul.com/?q=123', extra_data={'source': 'url'}, _source='gf', _type='tag'),
		Tag(name='lfi pattern', match='http://testphp.vulnweb.com/listproducts.php?cat=123&artist=123&asdf=ff', extra_data={'source': 'url'}, _source='gf', _type='tag'),
		Vulnerability(matched_at='http://testphp.vulnweb.com/listproducts.php', name='Grep XSS', provider='', id='', confidence='high', severity='low', cvss_score=0, tags=[], extra_data={'inject_type': 'BUILTIN', 'poc_type': 'plain', 'method': 'GET', 'data': 'http://testphp.vulnweb.com/listproducts.php?artist=123&asdf=ff&cat=%250d%250aDalfoxcrlf%3A+1234', 'param': '', 'payload': 'toGrepping', 'evidence': ''}, description='', references=[], reference='', confidence_nb=1, severity_nb=3, _source='dalfox', _type='vulnerability'),
		Vulnerability(matched_at='http://testphp.vulnweb.com/listproducts.php', name='Verified XSS', provider='', id='', confidence='high', severity='high', cvss_score=0, tags=['CWE-79'], extra_data={'inject_type': 'inHTML-none(1)-URL', 'poc_type': 'plain', 'method': 'GET', 'data': 'http://testphp.vulnweb.com/listproducts.php?artist=123&asdf=ff&cat=123%3Cdiv+contextmenu%3Dxss%3E%3Cp%3E1%3Cmenu+type%3Dcontext+class%3Ddalfox+id%3Dxss+onshow%3Dalert%281%29%3E%3C%2Fmenu%3E%3C%2Fdiv%3E', 'param': 'cat', 'payload': '<div contextmenu=xss><p>1<menu type=context class=dalfox id=xss onshow=alert(1)></menu></div>', 'evidence': ''}, description='', references=[], reference='', confidence_nb=1, severity_nb=1, _source='dalfox', _type='vulnerability'),
	]
}

OUTPUTS_SCANS = {
    'domain': [
		Url(url='http://testphp.vulnweb.com', host='44.228.249.3', status_code=200, title='Home of Acunetix Art', webserver='nginx/1.19.0', tech=['DreamWeaver', 'Nginx:1.19.0', 'PHP:5.6.40', 'Ubuntu'], content_type='text/html', content_length=4958, time=0.33789056, method='GET', words=514, lines=110, _source='httpx', _type='url'),
		Subdomain(host='www.testphp.vulnweb.com', domain='testphp.vulnweb.com', sources=['alienvault'], _source='subfinder', _type='subdomain'),
		Port(port=80, host='testphp.vulnweb.com', ip='44.228.249.3', state='open', service_name='nginx/1.19.0', cpes=['cpe:/a:igor_sysoev:nginx:1.19.0'], extra_data={'name': 'http', 'product': 'nginx', 'version': '1.19.0', 'method': 'probed', 'conf': '10', 'cpe': ['cpe:/a:igor_sysoev:nginx:1.19.0'], 'nmap_script': 'vulscan'}, _source='nmap', _type='port'),
		Url(url='http://testphp.vulnweb.com', host='44.228.249.3', status_code=200, title='Home of Acunetix Art', webserver='nginx/1.19.0', tech=['DreamWeaver', 'Nginx:1.19.0', 'PHP:5.6.40', 'Ubuntu'], content_type='text/html', content_length=4958, time=0.33146840099999997, method='GET', words=514, lines=110, _source='httpx', _type='url'),
		Url(url='http://testphp.vulnweb.com/artists.php?artist=1', host='44.228.249.3', status_code=200, title='artists', webserver='nginx/1.19.0', tech=['DreamWeaver', 'Nginx:1.19.0', 'PHP:5.6.40', 'Ubuntu'], content_type='text/html', content_length=6251, time=0.343856073, method='GET', words=701, lines=124, _source='httpx', _type='url'),
		Url(url='http://testphp.vulnweb.com/cart.php', host='44.228.249.3', status_code=200, title='you cart', webserver='nginx/1.19.0', tech=['DreamWeaver', 'Nginx:1.19.0', 'PHP:5.6.40', 'Ubuntu'], content_type='text/html', content_length=4903, time=0.328803742, method='GET', words=502, lines=109, _source='httpx', _type='url'),
		Url(url='http://testphp.vulnweb.com/disclaimer.php', host='44.228.249.3', status_code=200, title='disclaimer', webserver='nginx/1.19.0', tech=['DreamWeaver', 'Nginx:1.19.0', 'PHP:5.6.40', 'Ubuntu'], content_type='text/html', content_length=5524, time=0.336831965, method='GET', words=574, lines=115, _source='httpx', _type='url'),
		Url(url='http://testphp.vulnweb.com/guestbook.php', host='44.228.249.3', status_code=200, title='guestbook', webserver='nginx/1.19.0', tech=['DreamWeaver', 'Nginx:1.19.0', 'PHP:5.6.40', 'Ubuntu'], content_type='text/html', content_length=5390, time=0.33741627399999996, method='GET', words=515, lines=113, _source='httpx', _type='url'),
		Url(url='http://testphp.vulnweb.com/hpp', host='44.228.249.3', status_code=200, title='HTTP Parameter Pollution Example', webserver='nginx/1.19.0', tech=['Nginx:1.19.0', 'PHP:5.6.40', 'Ubuntu'], content_type='text/html', content_length=203, time=0.32281805, method='GET', words=7, lines=6, _source='httpx', _type='url'),
		Url(url='http://testphp.vulnweb.com/hpp/?pp=12', host='44.228.249.3', status_code=200, title='HTTP Parameter Pollution Example', webserver='nginx/1.19.0', tech=['Nginx:1.19.0', 'PHP:5.6.40', 'Ubuntu'], content_type='text/html', content_length=383, time=0.32998955999999996, method='GET', words=12, lines=6, _source='httpx', _type='url'),
		Url(url='http://testphp.vulnweb.com/hpp/params.php?p=valid&pp=12', host='44.228.249.3', status_code=200, title='', webserver='nginx/1.19.0', tech=['Nginx:1.19.0', 'PHP:5.6.40', 'Ubuntu'], content_type='text/html', content_length=7, time=0.335079538, method='GET', words=1, lines=1, _source='httpx', _type='url'),
		Url(url='http://testphp.vulnweb.com/index.php', host='44.228.249.3', status_code=200, title='Home of Acunetix Art', webserver='nginx/1.19.0', tech=['DreamWeaver', 'Nginx:1.19.0', 'PHP:5.6.40', 'Ubuntu'], content_type='text/html', content_length=4958, time=0.327651025, method='GET', words=514, lines=110, _source='httpx', _type='url'),
		Url(url='http://testphp.vulnweb.com/listproducts.php?cat=1', host='44.228.249.3', status_code=200, title='pictures', webserver='nginx/1.19.0', tech=['DreamWeaver', 'Nginx:1.19.0', 'PHP:5.6.40', 'Ubuntu'], content_type='text/html', content_length=7880, time=0.340787926, method='GET', words=640, lines=108, _source='httpx', _type='url'),
		Url(url='http://testphp.vulnweb.com/listproducts.php?artist=1', host='44.228.249.3', status_code=200, title='pictures', webserver='nginx/1.19.0', tech=['DreamWeaver', 'Nginx:1.19.0', 'PHP:5.6.40', 'Ubuntu'], content_type='text/html', content_length=7994, time=0.328947045, method='GET', words=653, lines=110, _source='httpx', _type='url'),
		Url(url='http://testphp.vulnweb.com/login.php', host='44.228.249.3', status_code=200, title='login page', webserver='nginx/1.19.0', tech=['DreamWeaver', 'Nginx:1.19.0', 'PHP:5.6.40', 'Ubuntu'], content_type='text/html', content_length=5523, time=0.337967283, method='GET', words=557, lines=120, _source='httpx', _type='url'),
		Url(url='http://testphp.vulnweb.com/Mod_Rewrite_Shop', host='44.228.249.3', status_code=200, title='', webserver='nginx/1.19.0', tech=['Nginx:1.19.0', 'PHP:5.6.40', 'Ubuntu'], content_type='text/html', content_length=975, time=0.335764248, method='GET', words=45, lines=4, _source='httpx', _type='url'),
		Url(url='http://testphp.vulnweb.com/Mod_Rewrite_Shop/Details/color-printer/3', host='44.228.249.3', status_code=200, title='', webserver='nginx/1.19.0', tech=['Nginx:1.19.0', 'PHP:5.6.40', 'Ubuntu'], content_type='text/html', content_length=313, time=0.326944514, method='GET', words=17, lines=2, _source='httpx', _type='url'),
		Url(url='http://testphp.vulnweb.com/Mod_Rewrite_Shop/Details/web-camera-a4tech/2', host='44.228.249.3', status_code=200, title='', webserver='nginx/1.19.0', tech=['Nginx:1.19.0', 'PHP:5.6.40', 'Ubuntu'], content_type='text/html', content_length=279, time=0.332789703, method='GET', words=11, lines=2, _source='httpx', _type='url'),
		Url(url='http://testphp.vulnweb.com/Mod_Rewrite_Shop/RateProduct-1.html', host='44.228.249.3', status_code=200, title='', webserver='nginx/1.19.0', tech=['Nginx:1.19.0', 'PHP:5.6.40', 'Ubuntu'], content_type='text/html', content_length=100, time=0.334238725, method='GET', words=12, lines=2, _source='httpx', _type='url'),
		Url(url='http://testphp.vulnweb.com/product.php?pic=1', host='44.228.249.3', status_code=200, title='picture details', webserver='nginx/1.19.0', tech=['DreamWeaver', 'Nginx:1.19.0', 'PHP:5.6.40', 'Ubuntu'], content_type='text/html', content_length=6428, time=0.325491191, method='GET', words=655, lines=117, _source='httpx', _type='url'),
		Url(url='http://testphp.vulnweb.com/secured/newuser.php', host='44.228.249.3', status_code=200, title='add new user', webserver='nginx/1.19.0', tech=['Nginx:1.19.0', 'PHP:5.6.40', 'Ubuntu'], content_type='text/html', content_length=415, time=0.323240657, method='GET', words=24, lines=16, _source='httpx', _type='url'),
		Url(url='http://testphp.vulnweb.com/search.php?test=query', host='44.228.249.3', status_code=200, title='search', webserver='nginx/1.19.0', tech=['DreamWeaver', 'Nginx:1.19.0', 'PHP:5.6.40', 'Ubuntu'], content_type='text/html', content_length=4732, time=0.332391097, method='GET', words=482, lines=104, _source='httpx', _type='url'),
		Url(url='http://testphp.vulnweb.com/showimage.php?file=./pictures/1.jpg', host='44.228.249.3', status_code=200, title='', webserver='nginx/1.19.0', tech=['Nginx:1.19.0', 'PHP:5.6.40', 'Ubuntu'], content_type='image/jpeg', content_length=12426, time=0.324003441, method='GET', words=53, lines=61, _source='httpx', _type='url'),
		Url(url='http://testphp.vulnweb.com/signup.php', host='44.228.249.3', status_code=200, title='signup', webserver='nginx/1.19.0', tech=['DreamWeaver', 'Nginx:1.19.0', 'PHP:5.6.40', 'Ubuntu'], content_type='text/html', content_length=6033, time=0.32592377, method='GET', words=547, lines=122, _source='httpx', _type='url'),
		Url(url='http://testphp.vulnweb.com/Templates/main_dynamic_template.dwt.php', host='44.228.249.3', status_code=200, title='Document titleg', webserver='nginx/1.19.0', tech=['Nginx:1.19.0', 'PHP:5.6.40', 'Ubuntu'], content_type='text/html', content_length=4697, time=0.33868919399999997, method='GET', words=480, lines=105, _source='httpx', _type='url'),
		Vulnerability(matched_at='http://testphp.vulnweb.com/hpp/', name='Verified XSS', provider='', id='', confidence='high', severity='high', cvss_score=0, tags=['CWE-83'], extra_data={'inject_type': 'inATTR-double(3)-URL', 'poc_type': 'plain', 'method': 'GET', 'data': 'http://testphp.vulnweb.com/hpp/?pp=12%22%22%3E%3CsVg%2Fonload%3Dprompt.valueOf%28%29%281%29+class%3Ddalfox%3E', 'param': 'pp', 'payload': '""><sVg/onload=prompt.valueOf()(1) class=dalfox>', 'evidence': '4 line:  ms.php?p=valid&pp=12""><sVg/onload=prompt.valueOf()(1) class=dalfox>">link2</a><'}, description='', references=[], reference='', confidence_nb=1, severity_nb=1, _source='dalfox', _type='vulnerability'),
		Vulnerability(matched_at='http://testphp.vulnweb.com/hpp/params.php', name='Verified XSS', provider='', id='', confidence='high', severity='high', cvss_score=0, tags=['CWE-79'], extra_data={'inject_type': 'inHTML-none(1)-URL', 'poc_type': 'plain', 'method': 'GET', 'data': 'http://testphp.vulnweb.com/hpp/params.php?p=valid&pp=12%3CiFrAme%2Fsrc%3DjaVascRipt%3Aalert.bind%28%29%281%29+class%3Ddalfox%3E%3C%2FiFramE%3E', 'param': 'pp', 'payload': '<iFrAme/src=jaVascRipt:alert.bind()(1) class=dalfox></iFramE>', 'evidence': '1 line:  valid12<iFrAme/src=jaVascRipt:alert.bind()(1) class=dalfox></iFramE>'}, description='', references=[], reference='', confidence_nb=1, severity_nb=1, _source='dalfox', _type='vulnerability'),
		Vulnerability(matched_at='http://testphp.vulnweb.com/hpp/params.php', name='Reflected XSS', provider='', id='', confidence='high', severity='medium', cvss_score=0, tags=['CWE-79'], extra_data={'inject_type': 'inHTML-URL', 'poc_type': 'plain', 'method': 'GET', 'data': 'http://testphp.vulnweb.com/hpp/params.php?p=valid%3Cxmp%3E%3Cp+title%3D%22%3C%2Fxmp%3E%3Csvg%2Fonload%3Dalert%281%29%3E&pp=12', 'param': 'p', 'payload': '<xmp><p title="</xmp><svg/onload=alert(1)>', 'evidence': '1 line:  valid<xmp><p title="</xmp><svg/onload=alert(1)>12'}, description='', references=[], reference='', confidence_nb=1, severity_nb=2, _source='dalfox', _type='vulnerability'),
		Vulnerability(matched_at='http://testphp.vulnweb.com/hpp/params.php', name='Verified XSS', provider='', id='', confidence='high', severity='high', cvss_score=0, tags=['CWE-79'], extra_data={'inject_type': 'inHTML-none(1)-URL', 'poc_type': 'plain', 'method': 'GET', 'data': 'http://testphp.vulnweb.com/hpp/params.php?p=valid%3CiFrAme%2Fsrc%3DjaVascRipt%3Aalert%281%29+class%3Ddalfox%3E%3C%2FiFramE%3E&pp=12', 'param': 'p', 'payload': '<iFrAme/src=jaVascRipt:alert(1) class=dalfox></iFramE>', 'evidence': '1 line:  valid<iFrAme/src=jaVascRipt:alert(1) class=dalfox></iFramE>12'}, description='', references=[], reference='', confidence_nb=1, severity_nb=1, _source='dalfox', _type='vulnerability'),
		Vulnerability(matched_at='http://testphp.vulnweb.com/hpp/params.php', name='Reflected XSS', provider='', id='', confidence='high', severity='medium', cvss_score=0, tags=['CWE-79'], extra_data={'inject_type': 'inHTML-none(1)-URL', 'poc_type': 'plain', 'method': 'GET', 'data': 'http://testphp.vulnweb.com/hpp/params.php?p=valid&pp=12%3CsVg%2Fonload%3Dprompt.valueOf%28%29%281%29%3E', 'param': 'pp', 'payload': '<sVg/onload=prompt.valueOf()(1)>', 'evidence': '1 line:  valid12<sVg/onload=prompt.valueOf()(1)>'}, description='', references=[], reference='', confidence_nb=1, severity_nb=2, _source='dalfox', _type='vulnerability'),
		Vulnerability(matched_at='http://testphp.vulnweb.com/listproducts.php', name='Verified XSS', provider='', id='', confidence='high', severity='high', cvss_score=0, tags=['CWE-79'], extra_data={'inject_type': 'inHTML-URL', 'poc_type': 'plain', 'method': 'GET', 'data': 'http://testphp.vulnweb.com/listproducts.php?cat=3%3C%2Fscript%3E%3Csvg%3E%3Cscript%2Fclass%3Ddalfox%3Ealert%281%29%3C%2Fscript%3E-%2526apos%3B', 'param': 'cat', 'payload': '</script><svg><script/class=dalfox>alert(1)</script>-%26apos;', 'evidence': ''}, description='', references=[], reference='', confidence_nb=1, severity_nb=1, _source='dalfox', _type='vulnerability'),
		Vulnerability(matched_at='http://testphp.vulnweb.com/listproducts.php', name='Reflected XSS', provider='', id='', confidence='high', severity='medium', cvss_score=0, tags=['CWE-79'], extra_data={'inject_type': 'inHTML-URL', 'poc_type': 'plain', 'method': 'GET', 'data': 'http://testphp.vulnweb.com/listproducts.php?cat=3%22%3Easd', 'param': 'cat', 'payload': '">asd', 'evidence': '48 line:  syntax to use near \'">asd\' at line 1'}, description='', references=[], reference='', confidence_nb=1, severity_nb=2, _source='dalfox', _type='vulnerability'),
		Vulnerability(matched_at='http://testphp.vulnweb.com/listproducts.php', name='Reflected XSS', provider='', id='', confidence='high', severity='medium', cvss_score=0, tags=['CWE-79'], extra_data={'inject_type': 'inHTML-URL', 'poc_type': 'plain', 'method': 'GET', 'data': 'http://testphp.vulnweb.com/listproducts.php?cat=4%22%3Easd', 'param': 'cat', 'payload': '">asd', 'evidence': '48 line:  syntax to use near \'">asd\' at line 1'}, description='', references=[], reference='', confidence_nb=1, severity_nb=2, _source='dalfox', _type='vulnerability'),
		Vulnerability(matched_at='http://testphp.vulnweb.com/listproducts.php', name='Reflected XSS', provider='', id='', confidence='high', severity='medium', cvss_score=0, tags=['CWE-79'], extra_data={'inject_type': 'inHTML-URL', 'poc_type': 'plain', 'method': 'GET', 'data': 'http://testphp.vulnweb.com/listproducts.php?cat=3%22%3E%3Cd3%22%3C%22%2Fonclick%3D%22%3E%5Bconfirm%60%60%5D%22%3C%22%3Ez', 'param': 'cat', 'payload': '"><d3"<"/onclick=">[confirm``]"<">z', 'evidence': '48 line:  syntax to use near \'"><d3"<"/onclick=">[confirm``]"<">z\' at line 1'}, description='', references=[], reference='', confidence_nb=1, severity_nb=2, _source='dalfox', _type='vulnerability'),
		Vulnerability(matched_at='http://testphp.vulnweb.com/listproducts.php', name='Reflected XSS', provider='', id='', confidence='high', severity='medium', cvss_score=0, tags=['CWE-79'], extra_data={'inject_type': 'inHTML-URL', 'poc_type': 'plain', 'method': 'GET', 'data': 'http://testphp.vulnweb.com/listproducts.php?cat=1%27%3E%3Cimg%2Fsrc%2Fonerror%3D.1%7Calert%60%60%3E', 'param': 'cat', 'payload': "'><img/src/onerror=.1|alert``>", 'evidence': "48 line:  syntax to use near ''><img/src/onerror=.1|alert``>' at line 1"}, description='', references=[], reference='', confidence_nb=1, severity_nb=2, _source='dalfox', _type='vulnerability'),
		Vulnerability(matched_at='http://testphp.vulnweb.com/listproducts.php', name='Verified XSS', provider='', id='', confidence='high', severity='high', cvss_score=0, tags=['CWE-79'], extra_data={'inject_type': 'inHTML-URL', 'poc_type': 'plain', 'method': 'GET', 'data': 'http://testphp.vulnweb.com/listproducts.php?cat=2%3C%2FScriPt%3E%3CsCripT+id%3Ddalfox%3Ealert%281%29%3C%2FsCriPt%3E', 'param': 'cat', 'payload': '</ScriPt><sCripT id=dalfox>alert(1)</sCriPt>', 'evidence': ''}, description='', references=[], reference='', confidence_nb=1, severity_nb=1, _source='dalfox', _type='vulnerability'),
		Vulnerability(matched_at='http://testphp.vulnweb.com/listproducts.php', name='Verified XSS', provider='', id='', confidence='high', severity='high', cvss_score=0, tags=['CWE-79'], extra_data={'inject_type': 'inHTML-URL', 'poc_type': 'plain', 'method': 'GET', 'data': 'http://testphp.vulnweb.com/listproducts.php?cat=4%27%22%3E%3Cimg%2Fsrc%2Fonerror%3D.1%7Calert%60%60+class%3Ddalfox%3E', 'param': 'cat', 'payload': '\'"><img/src/onerror=.1|alert`` class=dalfox>', 'evidence': '48 line:  syntax to use near \'\'"><img/src/onerror=.1|alert`` class=dalfox>\' at line 1'}, description='', references=[], reference='', confidence_nb=1, severity_nb=1, _source='dalfox', _type='vulnerability'),
		Vulnerability(matched_at='http://testphp.vulnweb.com/listproducts.php', name='Grep XSS', provider='', id='', confidence='high', severity='low', cvss_score=0, tags=[], extra_data={'inject_type': 'BUILTIN', 'poc_type': 'plain', 'method': 'GET', 'data': 'http://testphp.vulnweb.com/listproducts.php?cat=%2F%2F%2F%2F%255cgoogle.com', 'param': '', 'payload': 'toOpenRedirecting', 'evidence': ''}, description='', references=[], reference='', confidence_nb=1, severity_nb=3, _source='dalfox', _type='vulnerability'),
		Vulnerability(matched_at='http://testphp.vulnweb.com/listproducts.php', name='Reflected XSS', provider='', id='', confidence='high', severity='medium', cvss_score=0, tags=['CWE-79'], extra_data={'inject_type': 'inHTML-URL', 'poc_type': 'plain', 'method': 'GET', 'data': 'http://testphp.vulnweb.com/listproducts.php?cat=3%27%3E%3Cimg%2Fsrc%2Fonerror%3D.1%7Calert%60%60%3E', 'param': 'cat', 'payload': "'><img/src/onerror=.1|alert``>", 'evidence': "48 line:  syntax to use near ''><img/src/onerror=.1|alert``>' at line 1"}, description='', references=[], reference='', confidence_nb=1, severity_nb=2, _source='dalfox', _type='vulnerability'),
		Vulnerability(matched_at='http://testphp.vulnweb.com/listproducts.php', name='Verified XSS', provider='', id='', confidence='high', severity='high', cvss_score=0, tags=['CWE-79'], extra_data={'inject_type': 'inHTML-URL', 'poc_type': 'plain', 'method': 'GET', 'data': 'http://testphp.vulnweb.com/listproducts.php?cat=1%27%22%3E%3Cimg%2Fsrc%2Fonerror%3D.1%7Calert%60%60+class%3Ddalfox%3E', 'param': 'cat', 'payload': '\'"><img/src/onerror=.1|alert`` class=dalfox>', 'evidence': '48 line:  syntax to use near \'\'"><img/src/onerror=.1|alert`` class=dalfox>\' at line 1'}, description='', references=[], reference='', confidence_nb=1, severity_nb=1, _source='dalfox', _type='vulnerability'),
		Tag(name='lfi pattern', match='http://testphp.vulnweb.com/showimage.php?file=./pictures/1.jpg', extra_data={'source': 'url'}, _source='gf', _type='tag'),
		Tag(name='ssrf pattern', match='http://testphp.vulnweb.com/showimage.php?file=./pictures/1.jpg', extra_data={'source': 'url'}, _source='gf', _type='tag'),
		Tag(name='interestingparams pattern', match='http://testphp.vulnweb.com/showimage.php?file=./pictures/1.jpg', extra_data={'source': 'url'}, _source='gf', _type='tag'),
		Tag(name='lfi pattern', match='http://testphp.vulnweb.com/listproducts.php?cat=1', extra_data={'source': 'url'}, _source='gf', _type='tag'),
		Tag(name='xss pattern', match='http://testphp.vulnweb.com/hpp/?pp=12', extra_data={'source': 'url'}, _source='gf', _type='tag'),
		Tag(name='debug_logic pattern', match='http://testphp.vulnweb.com/search.php?test=query', extra_data={'source': 'url'}, _source='gf', _type='tag'),
		Tag(name='ssrf pattern', match='http://testphp.vulnweb.com/search.php?test=query', extra_data={'source': 'url'}, _source='gf', _type='tag'),
		Tag(name='interestingparams pattern', match='http://testphp.vulnweb.com/search.php?test=query', extra_data={'source': 'url'}, _source='gf', _type='tag'),
		Tag(name='xss pattern', match='http://testphp.vulnweb.com/hpp/params.php?p=valid&pp=12', extra_data={'source': 'url'}, _source='gf', _type='tag'),
	],
    'host': [
		Port(port=3000, host='localhost', ip='127.0.0.1', state='open', service_name='ppp', cpes=[], extra_data={'name': 'ppp', 'servicefp': 'SF-Port3000-TCP:V=7.80%I=7%D=4/13%Time=6438299D%P=x86_64-pc-linux-gnu%r(GetRequest,979,"HTTP/1\\.1\\x20200\\x20OK\\r\\nAccess-Control-Allow-Origin:\\x20\\*\\r\\nX-Content-Type-Options:\\x20nosniff\\r\\nX-Frame-Options:\\x20SAMEORIGIN\\r\\nFeature-Policy:\\x20payment\\x20\'self\'\\r\\nX-Recruiting:\\x20/#/jobs\\r\\nAccept-Ranges:\\x20bytes\\r\\nCache-Control:\\x20public,\\x20max-age=0\\r\\nLast-Modified:\\x20Thu,\\x2013\\x20Apr\\x202023\\x2016:09:42\\x20GMT\\r\\nETag:\\x20W/\\"7c3-1877b613b94\\"\\r\\nContent-Type:\\x20text/html;\\x20charset=UTF-8\\r\\nContent-Length:\\x201987\\r\\nVary:\\x20Accept-Encoding\\r\\nDate:\\x20Thu,\\x2013\\x20Apr\\x202023\\x2016:11:09\\x20GMT\\r\\nConnection:\\x20close\\r\\n\\r\\n<!--\\n\\x20\\x20~\\x20Copyright\\x20\\(c\\)\\x202014-2023\\x20Bjoern\\x20Kimminich\\x20&\\x20the\\x20OWASP\\x20Juice\\x20Shop\\x20contributors\\.\\n\\x20\\x20~\\x20SPDX-License-Identifier:\\x20MIT\\n\\x20\\x20--><!DOCTYPE\\x20html><html\\x20lang=\\"en\\"><head>\\n\\x20\\x20<meta\\x20charset=\\"utf-8\\">\\n\\x20\\x20<title>OWASP\\x20Juice\\x20Shop</title>\\n\\x20\\x20<meta\\x20name=\\"description\\"\\x20content=\\"Probably\\x20the\\x20most\\x20modern\\x20and\\x20sophisticated\\x20insecure\\x20web\\x20application\\">\\n\\x20\\x20<meta\\x20name=\\"viewport\\"\\x20content=\\"width=device-width,\\x20initial-scale=1\\">\\n\\x20\\x20<link\\x20id=\\"favicon\\"\\x20rel=\\"icon\\"\\x20type=\\"image/x-icon\\"\\x20href=\\"asset")%r(Help,2F,"HTTP/1\\.1\\x20400\\x20Bad\\x20Request\\r\\nConnection:\\x20close\\r\\n\\r\\n")%r(NCP,2F,"HTTP/1\\.1\\x20400\\x20Bad\\x20Request\\r\\nConnection:\\x20close\\r\\n\\r\\n")%r(HTTPOptions,EA,"HTTP/1\\.1\\x20204\\x20No\\x20Content\\r\\nAccess-Control-Allow-Origin:\\x20\\*\\r\\nAccess-Control-Allow-Methods:\\x20GET,HEAD,PUT,PATCH,POST,DELETE\\r\\nVary:\\x20Access-Control-Request-Headers\\r\\nContent-Length:\\x200\\r\\nDate:\\x20Thu,\\x2013\\x20Apr\\x202023\\x2016:11:09\\x20GMT\\r\\nConnection:\\x20close\\r\\n\\r\\n")%r(RTSPRequest,EA,"HTTP/1\\.1\\x20204\\x20No\\x20Content\\r\\nAccess-Control-Allow-Origin:\\x20\\*\\r\\nAccess-Control-Allow-Methods:\\x20GET,HEAD,PUT,PATCH,POST,DELETE\\r\\nVary:\\x20Access-Control-Request-Headers\\r\\nContent-Length:\\x200\\r\\nDate:\\x20Thu,\\x2013\\x20Apr\\x202023\\x2016:11:09\\x20GMT\\r\\nConnection:\\x20close\\r\\n\\r\\n");', 'method': 'table', 'conf': '3', 'nmap_script': 'fingerprint-strings'}, _source='nmap', _type='port'),
		Port(port=8080, host='localhost', ip='127.0.0.1', state='open', service_name='', cpes=[], extra_data={'name': 'nagios-nsca', 'product': 'nagios nsca', 'method': 'probed', 'conf': '10', 'nmap_script': 'vulscan'}, _source='nmap', _type='port'),
		Vulnerability(matched_at='http://localhost:3000', ip='127.0.0.1', name='FingerprintHub Technology Fingerprint - qm-system', provider='', id='', confidence='high', severity='info', cvss_score=0, tags=['tech'], extra_data={'data': []}, description='FingerprintHub Technology Fingerprint tests run in nuclei.', references=['https://github.com/0x727/fingerprinthub'], reference='https://github.com/0x727/fingerprinthub', confidence_nb=1, severity_nb=4, _source='nuclei', _type='vulnerability'),
		Vulnerability(matched_at='http://localhost:3000/api-docs/swagger.json', ip='127.0.0.1', name='Public Swagger API - Detect', provider='', id='', confidence='high', severity='info', cvss_score=0, tags=['exposure', 'api', 'swagger'], extra_data={'data': []}, description='Public Swagger API was detected.', references=['https://swagger.io/'], reference='https://swagger.io/', confidence_nb=1, severity_nb=4, _source='nuclei', _type='vulnerability'),
		Vulnerability(matched_at='http://localhost:3000/metrics', ip='127.0.0.1', name='Prometheus Metrics - Detect', provider='', id='', confidence='high', severity='medium', cvss_score=5.3, tags=['exposure', 'prometheus', 'hackerone', 'config'], extra_data={'data': []}, description='Prometheus metrics page was detected.', references=['https://github.com/prometheus/prometheus', 'https://hackerone.com/reports/1026196'], reference='https://github.com/prometheus/prometheus', confidence_nb=1, severity_nb=2, _source='nuclei', _type='vulnerability'),
		Vulnerability(matched_at='http://localhost:8080/', ip='127.0.0.1', name='Spring Boot - Remote Code Execution (Apache Log4j)', provider='', id='cve-2021-44228', confidence='high', severity='critical', cvss_score=10, tags=['cve', 'cve2021', 'springboot', 'rce', 'oast', 'log4j', 'kev'], extra_data={'data': ['192.221.154.139', 'f978d7010c8a']}, description='Spring Boot is susceptible to remote code execution via Apache Log4j.', references=['https://logging.apache.org/log4j/2.x/security.html', 'https://www.lunasec.io/docs/blog/log4j-zero-day/', 'https://github.com/twseptian/spring-boot-log4j-cve-2021-44228-docker-lab', 'https://nvd.nist.gov/vuln/detail/cve-2021-44228'], reference='https://logging.apache.org/log4j/2.x/security.html', confidence_nb=1, severity_nb=0, _source='nuclei', _type='vulnerability'),
		Url(url='http://localhost:3000', host='127.0.0.1', status_code=200, title='OWASP Juice Shop', webserver='', tech=[], content_type='text/html', content_length=1987, time=0.006561506999999999, method='GET', words=207, lines=30, _source='httpx', _type='url'),
		Url(url='http://localhost:8080', host='127.0.0.1', status_code=400, title='', webserver='', tech=[], content_type='application/json', content_length=91, time=0.005872706, method='GET', words=2, lines=1, _source='httpx', _type='url'),
		Url(url='http://localhost:3000/main.js', host='127.0.0.1', status_code=200, title='', webserver='', tech=[], content_type='application/javascript', content_length=399134, time=0.150468305, method='GET', words=6165, lines=1, _source='httpx', _type='url'),
		Url(url='http://localhost:3000/runtime.js', host='127.0.0.1', status_code=200, title='', webserver='', tech=[], content_type='application/javascript', content_length=3210, time=0.073505449, method='GET', words=63, lines=1, _source='httpx', _type='url'),
		Url(url='http://localhost:8080', host='127.0.0.1', status_code=400, title='', webserver='', tech=[], content_type='application/json', content_length=91, time=0.0023964050000000003, method='GET', words=2, lines=1, _source='httpx', _type='url'),
		Url(url='http://localhost:3000/polyfills.js', host='127.0.0.1', status_code=200, title='', webserver='', tech=[], content_type='application/javascript', content_length=54475, time=0.068285038, method='GET', words=1213, lines=1, _source='httpx', _type='url'),
		Url(url='http://localhost:3000/vendor.js', host='127.0.0.1', status_code=200, title='', webserver='', tech=[], content_type='application/javascript', content_length=1372534, time=0.366507142, method='GET', words=28278, lines=1, _source='httpx', _type='url'),
		Url(url='http://localhost:3000/styles.css', host='127.0.0.1', status_code=200, title='', webserver='', tech=[], content_type='text/css', content_length=609068, time=0.24081448700000002, method='GET', words=14024, lines=31, _source='httpx', _type='url'),
		Url(url='http://localhost:3000/sitemap.xml', host='127.0.0.1', status_code=200, title='OWASP Juice Shop', webserver='', tech=[], content_type='text/html', content_length=1987, time=0.061134424, method='GET', words=207, lines=30, _source='httpx', _type='url'),
		Url(url='http://localhost:3000', host='127.0.0.1', status_code=200, title='OWASP Juice Shop', webserver='', tech=[], content_type='text/html', content_length=1987, time=0.052648907, method='GET', words=207, lines=30, _source='httpx', _type='url'),
		Url(url='http://localhost:3000/assets/public/favicon_js.ico', host='127.0.0.1', status_code=200, title='', webserver='', tech=[], content_type='image/x-icon', content_length=15086, time=0.051407103999999995, method='GET', words=16, lines=6, _source='httpx', _type='url'),
		Url(url='http://localhost:3000/robots.txt', host='127.0.0.1', status_code=200, title='', webserver='', tech=[], content_type='text/plain', content_length=28, time=0.009132019, method='GET', words=3, lines=2, _source='httpx', _type='url')
	],
    'network': [],
    'url': []
}