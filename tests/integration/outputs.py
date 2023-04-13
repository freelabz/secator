from secsy.definitions import ROOT_FOLDER
from secsy.output_types import (Ip, Port, Subdomain, Tag, Url, UserAccount,
                                Vulnerability)

OUTPUTS_TASKS = {
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
            name='verify',
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

OUTPUTS_WORKFLOWS = {
    'cidr_recon': [
    	Ip(ip='127.0.0.1', host='', alive=True, _source='fping', _type='ip', _uuid='ea92f674-4cfe-4556-91f5-8669644513a0')
	],
    'code_scan': [
    	Vulnerability(matched_at=ROOT_FOLDER, name='CVE-2023-28859', provider='cve.circl.lu', id='CVE-2023-28859', confidence='low', severity='unknown', cvss_score=0, tags=['ghsa'], extracted_results={'product': 'redis', 'version': '4.5.4', 'product_type': 'python', 'ghsa_id': 'GHSA-8fww-64cx-x8p5'}, description='redis-py before 4.4.4 and 4.5.x before 4.5.4 leaves a connection open after canceling an async Redis command at an inopportune time, and can send response data to the client of an unrelated request. (This could, for example, happen for a non-pipeline operation.) NOTE: the solutions for  address data leakage across AsyncIO connections in general.', references=['https://cve.circl.lu/cve/CVE-2023-28859', 'https://github.com/redis/redis-py/pull/2641', 'https://github.com/redis/redis-py/issues/2665', 'https://github.com/redis/redis-py/releases/tag/v4.4.4', 'https://github.com/redis/redis-py/releases/tag/v4.5.4', 'https://github.com/redis/redis-py/pull/2666', 'https://cve.circl.lu/cve/CVE-2023-28859'], reference='https://cve.circl.lu/cve/CVE-2023-28859', confidence_nb=3, severity_nb=5, _source='grype', _type='vulnerability', _uuid='34788a02-98fc-45c9-845e-b8bec556730e'),
		Vulnerability(matched_at=ROOT_FOLDER, name='CVE-2023-28858', provider='cve.circl.lu', id='CVE-2023-28858', confidence='low', severity='unknown', cvss_score=0, tags=['ghsa'], extracted_results={'product': 'redis', 'version': '4.5.3', 'product_type': 'python', 'ghsa_id': 'GHSA-24wv-mv5m-xv4h'}, description='redis-py before 4.5.3 leaves a connection open after canceling an async Redis command at an inopportune time, and can send response data to the client of an unrelated request in an off-by-one manner. NOTE: this CVE Record was initially created in response to reports about ChatGPT, and 4.3.6, 4.4.3, and 4.5.3 were released (changing the behavior for pipeline operations); however, please see CVE-2023-28859 about addressing data leakage across AsyncIO connections in general.', references=['https://cve.circl.lu/cve/CVE-2023-28858', 'https://github.com/redis/redis-py/compare/v4.3.5...v4.3.6', 'https://github.com/redis/redis-py/pull/2641', 'https://openai.com/blog/march-20-chatgpt-outage', 'https://github.com/redis/redis-py/issues/2624', 'https://github.com/redis/redis-py/compare/v4.4.2...v4.4.3', 'https://github.com/redis/redis-py/compare/v4.5.2...v4.5.3', 'https://cve.circl.lu/cve/CVE-2023-28858'], reference='https://cve.circl.lu/cve/CVE-2023-28858', confidence_nb=3, severity_nb=5, _source='grype', _type='vulnerability', _uuid='7d00bd81-ffea-4512-94a5-c504c7867d30'),
		Vulnerability(matched_at=ROOT_FOLDER, name='Navigation Remapping To Propagate Malicious Content', provider='cve.circl.lu', id='CVE-2022-23491', confidence='low', severity='unknown', cvss_score=0, tags=['ghsa'], extracted_results={'product': 'certifi', 'version': '2022.12.07', 'product_type': 'python', 'ghsa_id': 'GHSA-43fp-rhv2-5gv8'}, description='Certifi is a curated collection of Root Certificates for validating the trustworthiness of SSL certificates while verifying the identity of TLS hosts. Certifi 2022.12.07 removes root certificates from "TrustCor" from the root store. These are in the process of being removed from Mozilla\'s trust store. TrustCor\'s root certificates are being removed pursuant to an investigation prompted by media reporting that TrustCor\'s ownership also operated a business that produced spyware. Conclusions of Mozilla\'s investigation can be found in the linked google group discussion.', references=['https://cve.circl.lu/cve/CVE-2022-23491', 'https://groups.google.com/a/mozilla.org/g/dev-security-policy/c/oxX69KFvsm4/m/yLohoVqtCgAJ', 'https://github.com/certifi/python-certifi/security/advisories/GHSA-43fp-rhv2-5gv8', 'https://cve.circl.lu/cve/CVE-2022-23491'], reference='https://cve.circl.lu/cve/CVE-2022-23491', confidence_nb=3, severity_nb=5, _source='grype', _type='vulnerability', _uuid='e38db120-c0fd-42e0-b393-297522e852d4')
	],
    'host_recon': [
		Port(port=8080, host='localhost', ip='127.0.0.1', service_name='', cpes=[], extra_data={'name': 'nagios-nsca', 'product': 'nagios nsca', 'method': 'probed', 'conf': '10', 'nmap_script': 'vulscan'}, _source='nmap', _type='port', _uuid='69d71843-798a-4934-a01c-7073955ac485'),
		Port(port=3000, host='localhost', ip='127.0.0.1', service_name='', cpes=[], extra_data={'name': 'ppp', 'conf': '3', 'nmap_script': 'fingerprint-strings'}, _source='nmap', _type='port', _uuid='cbc2bc2d-2cf8-4922-84e2-6a6cea9149dd'),
		Vulnerability(matched_at='http://localhost:8080/', name='Spring Boot - Remote Code Execution (Apache Log4j)', provider='', id='cve-2021-44228', confidence='high', severity='critical', cvss_score=10, tags=['cve', 'cve2021', 'springboot', 'rce', 'oast', 'log4j', 'kev'], extracted_results={'data': ['192.221.154.139', 'f978d7010c8a']}, description='Spring Boot is susceptible to remote code execution via Apache Log4j.', references=['https://logging.apache.org/log4j/2.x/security.html', 'https://www.lunasec.io/docs/blog/log4j-zero-day/', 'https://github.com/twseptian/spring-boot-log4j-cve-2021-44228-docker-lab', 'https://nvd.nist.gov/vuln/detail/cve-2021-44228'], reference='https://logging.apache.org/log4j/2.x/security.html', confidence_nb=1, severity_nb=0, _source='nuclei', _type='vulnerability', _uuid='3cec387f-ef54-401d-915e-5f361de7896c'),
		Vulnerability(matched_at='http://localhost:8080/error', name='Java Spring Detection', provider='', id='', confidence='high', severity='info', cvss_score=0, tags=['tech', 'java', 'spring'], extracted_results={'data': []}, description='', references=['https://mkyong.com/spring-boot/spring-rest-error-handling-example/'], reference='https://mkyong.com/spring-boot/spring-rest-error-handling-example/', confidence_nb=1, severity_nb=4, _source='nuclei', _type='vulnerability', _uuid='b2679953-434c-48f0-b182-95f2383462db'),
		Vulnerability(matched_at='http://localhost:3000', name='FingerprintHub Technology Fingerprint', provider='', id='', confidence='high', severity='info', cvss_score=0, tags=['tech'], extracted_results={'data': []}, description='FingerprintHub Technology Fingerprint tests run in nuclei.', references=['https://github.com/0x727/fingerprinthub'], reference='https://github.com/0x727/fingerprinthub', confidence_nb=1, severity_nb=4, _source='nuclei', _type='vulnerability', _uuid='32862d58-fe0b-4552-8422-f8980da7cd94'),
		Vulnerability(matched_at='http://localhost:3000', name='OWASP Juice Shop', provider='', id='', confidence='high', severity='info', cvss_score=0, tags=['tech', 'owasp'], extracted_results={'data': []}, description='', references=[], reference='', confidence_nb=1, severity_nb=4, _source='nuclei', _type='vulnerability', _uuid='7b00075d-9c85-4cf4-b1f7-1c2e15eb9c57'),
		Vulnerability(matched_at='http://localhost:3000/.well-known/security.txt', name='Security.txt File', provider='', id='', confidence='high', severity='info', cvss_score=0, tags=['misc', 'generic'], extracted_results={'data': [' mailto:donotreply@owasp-juice.shop']}, description='The website defines a security policy.', references=[], reference='', confidence_nb=1, severity_nb=4, _source='nuclei', _type='vulnerability', _uuid='35489dd0-28b1-4259-b756-6241d0ba8925'),
		Vulnerability(matched_at='http://localhost:3000/ftp', name='robots.txt endpoint prober', id='', confidence='high', severity='info', cvss_score=0, tags=[], extracted_results={'data': []}, description='', references=[], reference='', confidence_nb=1, severity_nb=4, _source='nuclei', _type='vulnerability', _uuid='060d58dd-42b2-4b84-a709-1a8da900eb88'),
		Vulnerability(matched_at='http://localhost:3000/metrics', name='Kubelet Metrics', provider='', id='', confidence='high', severity='info', cvss_score=0, tags=['tech', 'k8s', 'kubernetes', 'devops', 'kubelet'], extracted_results={'data': []}, description='Scans for kubelet metrics', references=[], reference='', confidence_nb=1, severity_nb=4, _source='nuclei', _type='vulnerability', _uuid='a76059f8-2aa1-4f9a-89b3-11d1fc6c0037'),
		Vulnerability(matched_at='http://localhost:3000/metrics', name='Prometheus Metrics - Detect', provider='', id='', confidence='high', severity='medium', cvss_score=5.3, tags=['exposure', 'prometheus', 'hackerone', 'config'], extracted_results={'data': []}, description='Prometheus metrics page was detected.', references=['https://github.com/prometheus/prometheus', 'https://hackerone.com/reports/1026196'], reference='https://github.com/prometheus/prometheus', confidence_nb=1, severity_nb=2, _source='nuclei', _type='vulnerability', _uuid='e71fb342-a479-4436-9f92-bcfb2672ef2f'),
		Vulnerability(matched_at='http://localhost:3000/api-docs/swagger.json', name='Public Swagger API - Detect', provider='', id='', confidence='high', severity='info', cvss_score=0, tags=['exposure', 'api', 'swagger'], extracted_results={'data': []}, description='Public Swagger API was detected.', references=['https://swagger.io/'], reference='https://swagger.io/', confidence_nb=1, severity_nb=4, _source='nuclei', _type='vulnerability', _uuid='a87a4210-d255-4546-acb1-a808490edd19'),
		Vulnerability(matched_at='http://localhost:3000/robots.txt', name='robots.txt endpoint prober', provider='', id='', confidence='high', severity='info', cvss_score=0, tags=[], extracted_results={'data': []}, description='', references=[], reference='', confidence_nb=1, severity_nb=4, _source='nuclei', _type='vulnerability', _uuid='d993890e-55a1-4d35-8bbe-53f3af89c9f5'),
		Url(url='http://localhost:8080', host='127.0.0.1', status_code=400, title='', webserver='', tech=[], content_type='application/json', content_length=91, time=0.00341461, method='GET', words=2, lines=1, _source='httpx', _type='url', _uuid='d26961c4-e955-4034-a52e-7f1b1a576d4c'),
		Url(url='http://localhost:3000', host='127.0.0.1', status_code=200, title='OWASP Juice Shop', webserver='', tech=[], content_type='text/html', content_length=1987, time=0.00350711, method='GET', words=207, lines=30, _source='httpx', _type='url', _uuid='f10f62fd-6eca-45e2-92b5-d90794b7613c')
	],
    'subdomain_recon': [
    	Subdomain(host='virusscan.api.github.com', domain='api.github.com', sources=['alienvault'], _source='subfinder', _type='subdomain', _uuid='0d2d410a-7495-48c2-a6ea-14aa2c6e449d'),
        Subdomain(host='virus.api.github.com', domain='api.github.com', sources=['alienvault'], _source='subfinder', _type='subdomain', _uuid='1bc1b33c-ba2e-44ed-8038-a3e344161931'),
        Vulnerability(matched_at='virusscan.api.github.com', name='CAA Record', provider='', id='', confidence='high', severity='info', cvss_score=0, tags=['dns', 'caa'], extracted_results={'data': ['digicert.com', 'letsencrypt.org']}, description='A CAA record was discovered. A CAA record is used to specify which certificate authorities (CAs) are allowed to issue certificates for a domain.', references=['https://support.dnsimple.com/articles/caa-record/#whats-a-caa-record'], reference='https://support.dnsimple.com/articles/caa-record/#whats-a-caa-record', confidence_nb=1, severity_nb=4, _source='nuclei', _type='vulnerability', _uuid='980198d7-baeb-4306-b14e-dee4875c2e6d'),
		Vulnerability(matched_at='virusscan.api.github.com', name='CNAME Fingerprint', provider='', id='', confidence='high', severity='info', cvss_score=0, tags=['dns', 'cname'], extracted_results={'data': ['github.github.io.']}, description='A CNAME DNS record was discovered.', references=['https://www.theregister.com/2021/02/24/dns_cname_tracking/', 'https://www.ionos.com/digitalguide/hosting/technical-matters/cname-record/'], reference='https://www.theregister.com/2021/02/24/dns_cname_tracking/', confidence_nb=1, severity_nb=4, _source='nuclei', _type='vulnerability', _uuid='75b51c7b-8d2a-470f-9b8e-9fcf1cb41a78'),
		Vulnerability(matched_at='virus.api.github.com', name='CAA Record', provider='', id='', confidence='high', severity='info', cvss_score=0, tags=['dns', 'caa'], extracted_results={'data': ['digicert.com', 'letsencrypt.org']}, description='A CAA record was discovered. A CAA record is used to specify which certificate authorities (CAs) are allowed to issue certificates for a domain.', references=['https://support.dnsimple.com/articles/caa-record/#whats-a-caa-record'], reference='https://support.dnsimple.com/articles/caa-record/#whats-a-caa-record', confidence_nb=1, severity_nb=4, _source='nuclei', _type='vulnerability', _uuid='cf3a6466-9e66-4307-8d37-d83948a37220'),
        Vulnerability(matched_at='virus.api.github.com', name='CNAME Fingerprint', provider='', id='', confidence='high', severity='info', cvss_score=0, tags=['dns', 'cname'], extracted_results={'data': ['github.github.io.']}, description='A CNAME DNS record was discovered.', references=['https://www.theregister.com/2021/02/24/dns_cname_tracking/', 'https://www.ionos.com/digitalguide/hosting/technical-matters/cname-record/'], reference='https://www.theregister.com/2021/02/24/dns_cname_tracking/', confidence_nb=1, severity_nb=4, _source='nuclei', _type='vulnerability', _uuid='5cca8c7f-1e2c-40cf-9941-73e17d85d485'),
        Url(url='https://virus.api.github.com', host='185.199.108.153', status_code=404, title='Site not found · GitHub Pages', webserver='GitHub.com', tech=['Fastly', 'GitHub Pages', 'Varnish'], content_type='text/html', content_length=9115, time=0.055734349, method='GET', words=641, lines=80, _source='httpx', _type='url', _uuid='97aca3a7-5c67-4905-9681-2d4d9f911df8'),
	],
    'user_hunt': [
    	UserAccount(site_name='Docker Hub', username='ocervell', url='https://hub.docker.com/u/ocervell/', _source='maigret', _type='user_account', _uuid='1115909f-a321-4441-b0a5-2fe4fd3c768b'),
        UserAccount(site_name='PyPi', username='ocervell', url='https://pypi.org/user/ocervell', _source='maigret', _type='user_account', _uuid='86eb7119-e605-4b39-9f9a-ae792d2392c8'),
        UserAccount(site_name='GitHub', username='ocervell', url='https://github.com/ocervell', _source='maigret', _type='user_account', _uuid='fde8a195-e9c1-48da-9d5d-f332cac2d25d'),
	],
    'url_nuclei': [
    	Vulnerability(matched_at='http://localhost:3000/metrics', name='Prometheus Metrics - Detect', provider='', id='', confidence='high', severity='medium', cvss_score=5.3, tags=['exposure', 'prometheus', 'hackerone', 'config'], extracted_results={'data': []}, description='Prometheus metrics page was detected.', references=['https://github.com/prometheus/prometheus', 'https://hackerone.com/reports/1026196'], reference='https://github.com/prometheus/prometheus', confidence_nb=1, severity_nb=2, _source='nuclei', _type='vulnerability', _uuid='4cdda858-8c69-4dcb-a5b0-6f6d5567332c'),
		Vulnerability(matched_at='http://localhost:3000/metrics', name='Kubelet Metrics', provider='', id='', confidence='high', severity='info', cvss_score=0, tags=['tech', 'k8s', 'kubernetes', 'devops', 'kubelet'], extracted_results={'data': []}, description='Scans for kubelet metrics', references=[], reference='', confidence_nb=1, severity_nb=4, _source='nuclei', _type='vulnerability', _uuid='5f862e5f-1b67-479a-a36d-202d3723f391'),
        Vulnerability(matched_at='http://localhost:3000/api-docs/swagger.json', name='Public Swagger API - Detect', provider='', id='', confidence='high', severity='info', cvss_score=0, tags=['exposure', 'api', 'swagger'], extracted_results={'data': []}, description='Public Swagger API was detected.', references=['https://swagger.io/'], reference='https://swagger.io/', confidence_nb=1, severity_nb=4, _source='nuclei', _type='vulnerability', _uuid='6cb542cc-96c3-4be7-b6b6-ad855dc19736'),
	],
    'url_crawl': [
		Url(url='http://localhost:3000', host='127.0.0.1', status_code=200, title='OWASP Juice Shop', webserver='', tech=[], content_type='text/html', content_length=1987, time=0.031154163000000002, method='GET', words=207, lines=30, _source='httpx', _type='url', _uuid='e6b43434-5dc6-4ea5-9ccd-f610b40929ec'),
		Url(url='http://localhost:3000/runtime.js', host='127.0.0.1', status_code=200, title='', webserver='', tech=[], content_type='application/javascript', content_length=3210, time=0.024072803, method='GET', words=63, lines=1, _source='httpx', _type='url', _uuid='1b3d5c77-42cd-4e6d-a651-2d804e3f181d'),
		Url(url='http://localhost:3000/main.js', host='127.0.0.1', status_code=200, title='', webserver='', tech=[], content_type='application/javascript', content_length=399134, time=0.075288438, method='GET', words=6165, lines=1, _source='httpx', _type='url', _uuid='21db9fc6-4cd1-4411-8c35-8de6af8c1a0a'),
		Url(url='http://localhost:3000/polyfills.js', host='127.0.0.1', status_code=200, title='', webserver='', tech=[], content_type='application/javascript', content_length=54475, time=0.046900798, method='GET', words=1213, lines=1, _source='httpx', _type='url', _uuid='3f3ba72b-8a72-4304-9c65-b8a2a9f73051'),
		Url(url='http://localhost:3000/robots.txt', host='127.0.0.1', status_code=200, title='', webserver='', tech=[], content_type='text/plain', content_length=28, time=0.004258536, method='GET', words=3, lines=2, _source='httpx', _type='url', _uuid='6933033a-3064-40b1-b10c-64c908e8c82f'),
		Url(url='http://localhost:3000/styles.css', host='127.0.0.1', status_code=200, title='', webserver='', tech=[], content_type='text/css', content_length=609068, time=0.129273694, method='GET', words=14024, lines=31, _source='httpx', _type='url', _uuid='c84ccaba-b1df-41fa-b81d-411b53068d34'),
		Url(url='http://localhost:3000/sitemap.xml', host='127.0.0.1', status_code=200, title='OWASP Juice Shop', webserver='', tech=[], content_type='text/html', content_length=1987, time=0.031110464, method='GET', words=207, lines=30, _source='httpx', _type='url', _uuid='d90ee1f1-7c6a-4901-86d3-a7dd4d7da660'),
		Url(url='http://localhost:3000/assets/public/favicon_js.ico', host='127.0.0.1', status_code=200, title='', webserver='', tech=[], content_type='image/x-icon', content_length=15086, time=0.030026154, method='GET', words=16, lines=6, _source='httpx', _type='url', _uuid='f421e8a4-3d8e-45ec-8110-33f540b9be3e'),
	],
	'url_fuzz': [
		Url(url='http://localhost:3000/ftp', host='127.0.0.1', status_code=200, title='listing directory /ftp', webserver='', tech=[], content_type='text/html', content_length=11082, time=0.39357221, method='GET', words=1558, lines=357, _source='httpx', _type='url', _uuid='10af3633-5e98-41cb-8962-0e4c236573d9'),
		Url(url='http://localhost:3000/robots.txt', host='127.0.0.1', status_code=200, title='', webserver='', tech=[], content_type='text/plain', content_length=28, time=0.161848739, method='GET', words=3, lines=2, _source='httpx', _type='url', _uuid='a7137e28-e118-4ce3-9c67-e240604a7f16'),
		Url(url='http://localhost:3000/snippets', host='127.0.0.1', status_code=200, title='', webserver='', tech=[], content_type='application/json', content_length=707, time=0.18883662799999998, method='GET', words=1, lines=1, _source='httpx', _type='url', _uuid='9cb06266-c94c-4345-b2a9-20cba50262d7'),
		Url(url='http://localhost:3000/video', host='127.0.0.1', status_code=200, title='', webserver='', tech=[], content_type='video/mp4', content_length=10075518, time=2.432185494, method='GET', words=50020, lines=49061, _source='httpx', _type='url', _uuid='c81c8a42-296d-461b-b1b7-c166e398e827'),
	],
    'url_vuln': [
		Tag(name='xss', match='https://www.hahwul.com/?q=123', extra_data={'source': 'url'}, _source='gf', _type='tag', _uuid='16b27b1e-adb0-48e9-a8f9-87a1f38dd3a6'),
		Tag(name='lfi', match='http://testphp.vulnweb.com/listproducts.php?cat=123&artist=123&asdf=ff', extra_data={'source': 'url'}, _source='gf', _type='tag', _uuid='cfcba271-eca6-455c-b426-cfd76bb92ebb'),
		Vulnerability(matched_at='http://testphp.vulnweb.com/listproducts.php', name='grep', provider='', id='', confidence='high', severity='low', cvss_score=0, tags=[], extracted_results={'inject_type': 'BUILTIN', 'poc_type': 'plain', 'method': 'GET', 'data': 'http://testphp.vulnweb.com/listproducts.php?artist=123&asdf=ff&cat=%250d%250aDalfoxcrlf%3A+1234', 'param': '', 'payload': 'toGrepping', 'evidence': ''}, description='', references=[], reference='', confidence_nb=1, severity_nb=3, _source='dalfox', _type='vulnerability', _uuid='029214fe-21f7-40ed-b50a-b33772519ddc'),
		Vulnerability(matched_at='http://testphp.vulnweb.com/listproducts.php', name='grep', provider='', id='', confidence='high', severity='low', cvss_score=0, tags=[], extracted_results={'inject_type': 'BUILTIN', 'poc_type': 'plain', 'method': 'GET', 'data': 'http://testphp.vulnweb.com/listproducts.php?artist=123&asdf=ff&cat=%2F%2F%2Fwww.google.com%2F%252e%252e%252f', 'param': '', 'payload': 'toOpenRedirecting', 'evidence': ''}, description='', references=[], reference='', confidence_nb=1, severity_nb=3, _source='dalfox', _type='vulnerability', _uuid='9b4a2b85-671b-4786-8e6c-ccfad92ea9a4'),
		Vulnerability(matched_at='http://testphp.vulnweb.com/listproducts.php', name='reflected', provider='', id='', confidence='high', severity='medium', cvss_score=0, tags=['CWE-79'], extracted_results={'inject_type': 'inHTML-URL', 'poc_type': 'plain', 'method': 'GET', 'data': 'http://testphp.vulnweb.com/listproducts.php?artist=123&asdf=ff&cat=123%22%3E%3Cscript%2F%22%3Ca%22%2Fsrc%3Ddata%3A%3D%22.%3Ca%2C%5B%5D.some%28confirm%29%3E', 'param': 'cat', 'payload': '"><script/"<a"/src=data:=".<a,[].some(confirm)>', 'evidence': '48 line:  syntax to use near \'"><script/"<a"/src=data:=".<a,[].some(confirm)>\' at line 1'}, description='', references=[], reference='', confidence_nb=1, severity_nb=2, _source='dalfox', _type='vulnerability', _uuid='1562e677-d221-4881-becd-2c02a8f73a89'),
		Vulnerability(matched_at='http://testphp.vulnweb.com/listproducts.php', name='reflected', provider='', id='', confidence='high', severity='medium', cvss_score=0, tags=['CWE-79'], extracted_results={'inject_type': 'inHTML-URL', 'poc_type': 'plain', 'method': 'GET', 'data': 'http://testphp.vulnweb.com/listproducts.php?artist=123&asdf=ff&cat=123%27%3E%3Cimg%2Fsrc%2Fonerror%3D.1%7Calert%60%60%3E', 'param': 'cat', 'payload': "'><img/src/onerror=.1|alert``>", 'evidence': "48 line:  syntax to use near ''><img/src/onerror=.1|alert``>' at line 1"}, description='', references=[], reference='', confidence_nb=1, severity_nb=2, _source='dalfox', _type='vulnerability', _uuid='f0b44130-1ff1-4f19-a574-d46fa4528e78'),
		Vulnerability(matched_at='http://testphp.vulnweb.com/listproducts.php', name='verify', provider='', id='', confidence='high', severity='high', cvss_score=0, tags=['CWE-79'], extracted_results={'inject_type': 'inHTML-none(1)-URL', 'poc_type': 'plain', 'method': 'GET', 'data': 'http://testphp.vulnweb.com/listproducts.php?artist=123&asdf=ff&cat=123%3Cdiv+contextmenu%3Dxss%3E%3Cp%3E1%3Cmenu+type%3Dcontext+class%3Ddalfox+id%3Dxss+onshow%3Dalert%281%29%3E%3C%2Fmenu%3E%3C%2Fdiv%3E', 'param': 'cat', 'payload': '<div contextmenu=xss><p>1<menu type=context class=dalfox id=xss onshow=alert(1)></menu></div>', 'evidence': ''}, description='', references=[], reference='', confidence_nb=1, severity_nb=1, _source='dalfox', _type='vulnerability', _uuid='640f5644-b0a0-4e46-a82f-121a8dde74b2'),
	]
}

OUTPUTS_SCANS = {
    'domain': [],
    'host': [],
    'network': [],
    'url': []
}