<h1 align="center">
	secator
	<br>
</h1>

<h4 align="center">Security swiss-knife to speed up vulnerability assessments.</h4>

<p align="center">
<!-- <a href="https://goreportcard.com/report/github.com/freelabz/secator"><img src="https://goreportcard.com/badge/github.com/freelabz/secator"></a> -->
<a href="https://github.com/freelabz/secator/issues"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat"></a>
<a href="https://github.com/freelabz/secator/releases"><img src="https://img.shields.io/github/release/freelabz/secator"></a>
<a href="https://www.apache.org/licenses/LICENSE-2.0"><img src="https://img.shields.io/badge/License-Apache-blue.svg"></a>
<a href="https://twitter.com/freelabz"><img src="https://img.shields.io/twitter/follow/freelabz.svg?logo=twitter"></a>
<!-- <a href="https://discord.gg/freelabz"><img src="https://img.shields.io/discord/695645237418131507.svg?logo=discord"></a> -->
</p>


<p align="center">
  <a href="#features">Features</a> •
  <a href="#supported-commands">Supported commands</a> •
  <a href="#install-secator">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="https://docs.freelabz.com">Documentation</a>
</p>

`secator` is a task and workflow runner used for security assessments. It supports dozens of well-known security tools
and it is designed to improve productivity for pentesters and security researchers.

# Features

![](images/short_demo.gif)

* **Curated list of commands**

* **Unified input options**

* **Unified output schema**

* **CLI and library usage**

* **Distributed options with Celery**

* **Complexity from simple tasks to complex workflows**

* **Customizable**

## Supported commands

`secator` integrates the following commands:

| Name                                                          | Description                                                                    | Category       |
|---------------------------------------------------------------|--------------------------------------------------------------------------------|----------------|
| [httpx](https://github.com/projectdiscovery/httpx)            | Fast HTTP prober.                                                              | `http`         |
| [cariddi](https://github.com/edoardottt/cariddi)              | Fast crawler and endpoint secrets / api keys / tokens matcher.                 | `http/crawler` |
| [gau](https://github.com/lc/gau)                              | Offline URL crawler (Alien Vault, The Wayback Machine, Common Crawl, URLScan). | `http/crawler` |
| [gospider](https://github.com/jaeles-project/gospider)        | Fast web spider written in Go.                                                 | `http/crawler` |
| [katana](https://github.com/projectdiscovery/katana)          | Next-generation crawling and spidering framework.                              | `http/crawler` |
| [dirsearch](https://github.com/maurosoria/dirsearch)          | Web path discovery.                                                            | `http/fuzzer`  |
| [feroxbuster](https://github.com/epi052/feroxbuster)          | Simple, fast, recursive content discovery tool written in Rust.                | `http/fuzzer`  |
| [ffuf](https://github.com/ffuf/ffuf)                          | Fast web fuzzer written in Go.                                                 | `http/fuzzer`  |
| [h8mail](https://github.com/khast3x/h8mail)                   | Email OSINT and breach hunting tool.                                           | `osint`        |
| [dnsx](https://github.com/projectdiscovery/dnsx)              | Fast and multi-purpose DNS toolkit designed for running DNS queries.           | `recon/dns`    |
| [dnsxbrute](https://github.com/projectdiscovery/dnsx)              | Fast and multi-purpose DNS toolkit designed for running DNS queries (bruteforce mode).           | `recon/dns`    |
| [subfinder](https://github.com/projectdiscovery/subfinder)    | Fast subdomain finder.                                                         | `recon/dns`    |
| [fping](https://fping.org/)                                   | Find alive hosts on local networks.                                            | `recon/ip`     |
| [mapcidr](https://github.com/projectdiscovery/mapcidr)        | Expand CIDR ranges into IPs.                                                   | `recon/ip`     |
| [naabu](https://github.com/projectdiscovery/naabu)            | Fast port discovery tool.                                                      | `recon/port`   |
| [maigret](https://github.com/soxoj/maigret)                   | Hunt for user accounts across many websites.                                   | `recon/user`   |
| [gf](https://github.com/tomnomnom/gf)                         | A wrapper around grep to avoid typing common patterns.                         | `tagger`       |
| [grype](https://github.com/anchore/grype)                     | A vulnerability scanner for container images and filesystems.                  | `vuln/code`    |
| [dalfox](https://github.com/hahwul/dalfox)                    | Powerful XSS scanning tool and parameter analyzer.                             | `vuln/http`    |
| [msfconsole](https://docs.rapid7.com/metasploit/msf-overview) | CLI to access and work with the Metasploit Framework.                          | `vuln/http`    |
| [wpscan](https://github.com/wpscanteam/wpscan)                | WordPress Security Scanner                                                     | `vuln/multi`   |
| [nmap](https://github.com/nmap/nmap)                          | Vulnerability scanner using NSE scripts.                                       | `vuln/multi`   |
| [nuclei](https://github.com/projectdiscovery/nuclei)          | Fast and customisable vulnerability scanner based on simple YAML based DSL.    | `vuln/multi`   |
| [searchsploit](https://gitlab.com/exploit-database/exploitdb) | Exploit searcher. | `exploit/search`    |

Feel free to request new commands to be added by opening an issue, but please 
check that the command complies with our selection criterias before doing so. If it doesn't but you still want to integrate it into `secator`, you can plug it in (see the [dev guide](https://docs.freelabz.com/for-developers/writing-custom-tasks)).


## Install Secator

Secator requires **python >= 3.8** to install successfully. Run the following command to install the latest version:

```sh
pip3 install git+https://github.com/freelabz/secator.git
```

<details>
	<summary>Bash one-liner</summary>

	git clone https://github.com/freelabz/secator && sh ./scripts/install.sh

</details>

<details>
	<summary>Docker</summary>

	docker build -t secator

</details>

<details>
	<summary>Development build</summary>

	git clone https://github.com/freelabz/secator
	cd secator
	python3 -m virtualenv -p python3 ~/.virtualenvs/secator
	source ~/.virtualenvs/secator/bin/activate
	pip3 install -e .

</details>


### Install specific tasks

```sh
secator u install <TASK_NAME>
```

## Usage
```sh
secator --help
```
![](images/help.png)


### Running secator

Run a fuzzing task (`ffuf`):

```sh
secator x ffuf http://testphp.vulnweb.com/FUZZ
```

Run a port scan:

```sh
secator w port_scan mydomain.com
```

Run a full host scan:

```sh
secator s host mydomain.com
```

For more, read the complete [documentation](https://docs.freelabz.com).
