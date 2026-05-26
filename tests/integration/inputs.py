from secator.definitions import CIDR_RANGE, HOST, IP, ROOT_FOLDER, URL, USERNAME

INPUTS_TASKS = {
	URL: 'http://localhost:3000/',
	HOST: 'localhost',
	USERNAME: 'ocervell',
	IP: '127.0.0.1',
	CIDR_RANGE: '192.168.1.0/24',
	'getasn': 'tesla',
	'arjun': 'https://xss-game.appspot.com/level1/frame',
    'bbot': False, # disable bbot test
	'bup': 'http://localhost:3000/ftp/coupons_2013.md.bak',
	'dalfox': 'https://xss-game.appspot.com/level1/frame?query=',
	'dnsx': 'wikipedia.org',
	'ffuf': 'http://localhost:3000/FUZZ',
	'gau': 'https://xss-game.appspot.com',
	'gf': 'http://localhost:3000?q=test',
    'gitleaks': str(ROOT_FOLDER),
	'gospider': 'https://danielmiessler.com/',
	'grype': 'redis:7.4.1',
    'httpx': 'http://localhost:3000/',
	'h8mail': 'test@test.com',
	'jswhois': 'wikipedia.org',
	'nuclei': 'http://localhost:3000/',
	'searchsploit': 'apache 2.4.5',
	'subfinder': 'github.com',
	'search_vulns': 'apache 2.4.39',
	'testssl': 'free.fr',
	'trivy': 'https://github.com/blacklanternsecurity/bbot',
	'trufflehog': 'https://github.com/dehvCurtis/vulnerable-code-examples',
	'urlfinder': 'xss-game.appspot.com',
	'wpscan': 'http://localhost:8000/',
	'wafw00f': 'https://netflix.com',
	'whois': 'vulnweb.com',
	'whoisdomain': 'wikipedia.org',
	'x8': 'https://xss-game.appspot.com/level1/frame',
	'xurlfind3r': 'https://xss-game.appspot.com',
}

INPUTS_WORKFLOWS = {
	'cidr_recon': '127.0.0.1/30',
	'code_scan': str(ROOT_FOLDER),
	# 'dir_finder': 'localhost:3000',  # TODO: add fixture with directories
	'host_recon': 'secator.cloud',
	'subdomain_recon': 'api.github.com',
	'url_crawl': 'localhost:3000',
	'url_fuzz': 'http://localhost:3000',
	'url_nuclei': ['http://localhost:3000', 'http://localhost:8080'],
	'url_vuln': ['https://xss-game.appspot.com/level1/frame?query=', 'https://www.hahwul.com/?q=123'],
	'user_hunt': 'ocervell'
}

INPUTS_SCANS = {
	'domain': 'testphp.vulnweb.com',
	'host': ['localhost'],
	'network': '127.0.0.1/24',
	'url': ['http://localhost:3000', 'http://localhost:8080']
}
