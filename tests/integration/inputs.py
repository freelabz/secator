from secsy.definitions import CIDR_RANGE, HOST, IP, ROOT_FOLDER, URL, USERNAME

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

INPUTS_WORKFLOWS = {
	# 'cidr_recon': '127.0.0.1/24',
    # 'code_scan': ROOT_FOLDER,
    # 'dir_finder': 'localhost:3000',  # TODO: add fixture with directories
    # 'host_recon': 'localhost',
	# 'subdomain_recon': 'api.github.com',
    # 'url_crawl': 'localhost:3000',
    'url_fuzz': 'localhost:3000',
    'url_nuclei': ['http://localhost:3000', 'http://localhost:8080'],
    'url_vuln': 'localhost:3000',
    # 'user_hunt': 'ocervell'
}