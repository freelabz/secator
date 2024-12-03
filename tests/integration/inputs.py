from secator.definitions import CIDR_RANGE, HOST, IP, ROOT_FOLDER, URL, USERNAME

INPUTS_TASKS = {
    URL: 'http://localhost:3000/',
    HOST: 'localhost',
    USERNAME: 'ocervell',
    IP: '127.0.0.1',
    CIDR_RANGE: '192.168.1.0/24',
	'bup': 'http://localhost:3000/ftp/coupons_2013.md.bak',
    'dalfox': 'http://testphp.vulnweb.com/listproducts.php?cat=123&artist=123&asdf=ff',
    'ffuf': 'http://localhost:3000/FUZZ',
    'gf': 'http://localhost:3000?q=test',
    'gau': 'http://testphp.vulnweb.com',
    'gospider': 'https://danielmiessler.com/',
    'grype': 'redis:7.4.1',
    'nuclei': 'http://localhost:3000/',
	'searchsploit': 'apache 2.4.5',
    'subfinder': 'api.github.com',
    'wpscan': 'http://localhost:8000/',
    'h8mail': 'test@test.com',
    'dnsx': 'wikipedia.org',
    'dnsxbrute': 'wikipedia.org'
}

INPUTS_WORKFLOWS = {
	'cidr_recon': '127.0.0.1/30',
    'code_scan': str(ROOT_FOLDER),
    # 'dir_finder': 'localhost:3000',  # TODO: add fixture with directories
    'host_recon': 'localhost',
	'subdomain_recon': 'api.github.com',
    'url_crawl': 'localhost:3000',
    'url_fuzz': 'http://localhost:3000',
    'url_nuclei': ['http://localhost:3000', 'http://localhost:8080'],
    'url_vuln': ['http://testphp.vulnweb.com/listproducts.php?cat=123&artist=123&asdf=ff', 'https://www.hahwul.com/?q=123'],
    'user_hunt': 'ocervell'
}

INPUTS_SCANS = {
    'domain': 'testphp.vulnweb.com',
    'host': ['localhost'],
    'network': '127.0.0.1/24',
    'url': ['http://localhost:3000', 'http://localhost:8080']
}