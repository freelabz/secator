<h1 align="center">
    <img src="https://github.com/freelabz/secator/assets/9629314/ee203af4-e853-439a-af01-edeabfc4bf07/" width="400">
</h1>

<h4 align="center">The pentester's swiss knife.</h4>

<p align="center">
<!-- <a href="https://goreportcard.com/report/github.com/freelabz/secator"><img src="https://goreportcard.com/badge/github.com/freelabz/secator"></a> -->
<img src="https://img.shields.io/badge/python-3.6-blue.svg">
<a href="https://github.com/freelabz/secator/releases"><img src="https://img.shields.io/github/release/freelabz/secator"></a>
<a href="https://github.com/freelabz/secator/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-BSL%201.1-brightgreen.svg"></a>
<a href="https://pypi.org/project/secator/"><img src="https://img.shields.io/pypi/dm/secator"></a>
<a href="https://twitter.com/freelabz"><img src="https://img.shields.io/twitter/follow/freelabz.svg?logo=twitter"></a>
<a href="https://youtube.com/@FreeLabz"><img src="https://img.shields.io/youtube/channel/subscribers/UCu-F6SpU0h2NP18zBBP04cw?style=social&label=Subscribe%20%40FreeLabz"></a>
<a href="https://discord.gg/nyHjC2aTrq"><img src="https://img.shields.io/discord/695645237418131507.svg?logo=discord"></a>
</p>


<p align="center">
  <a href="#features">Features</a> •
  <a href="#supported-commands">Supported commands</a> •
  <a href="#install-secator">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="https://docs.freelabz.com">Documentation</a>  •
  <a href="https://discord.gg/nyHjC2aTrq">Join us on Discord !</a>
</p>

`secator` is a task and workflow runner used for security assessments. It supports dozens of well-known security tools
and it is designed to improve productivity for pentesters and security researchers.

# Features

![](images/demo.gif)

* **Curated list of commands**

* **Unified input options**

* **Unified output schema**

* **CLI and library usage**

* **Distributed options with Celery**

* **Complexity from simple tasks to complex workflows**

* **Customizable**


## Supported tools

`secator` integrates the following tools:

<!-- START_TOOLS_TABLE -->
| Name                                                            | Description                                                                      | Category          |
|-----------------------------------------------------------------|----------------------------------------------------------------------------------|-------------------|
| [arjun](https://github.com/s0md3v/Arjun)                                                           | HTTP Parameter Discovery Suite.                                                  | `url/fuzz/params` |
| [bbot](https://github.com/blacklanternsecurity/bbot)                                                            | Multipurpose scanner.                                                            | `vuln/scan`       |
| [bup](https://github.com/laluka/bypass-url-parser)                                                             | 40X bypasser.                                                                    | `url/bypass`      |
| [cariddi](https://github.com/edoardottt/cariddi)                                                         | Crawl endpoints, secrets, api keys, extensions, tokens...                        | `url/crawl`       |
| [dalfox](https://github.com/hahwul/dalfox)                                                          | Powerful open source XSS scanning tool.                                          | `url/fuzz`        |
| [dirsearch](https://github.com/maurosoria/dirsearch)                                                       | Advanced web path brute-forcer.                                                  | `url/fuzz`        |
| [dnsx](https://github.com/projectdiscovery/dnsx)                                                            | dnsx is a fast and multi-purpose DNS toolkit designed for running various retryabledns library. | `dns/fuzz`        |
| [feroxbuster](https://github.com/epi052/feroxbuster)                                                     | Simple, fast, recursive content discovery tool written in Rust                   | `url/fuzz`        |
| [ffuf](https://github.com/ffuf/ffuf)                                                            | Fast web fuzzer written in Go.                                                   | `url/fuzz`        |
| [fping](https://github.com/schweikert/fping)                                                           | Send ICMP echo probes to network hosts, similar to ping, but much better.        | `ip/recon`        |
| [gau](https://github.com/lc/gau)                                                             | Fetch known URLs from AlienVault's Open Threat Exchange, the Wayback Machine, Common Crawl, and URLScan. | `pattern/scan`    |
| [gf](https://github.com/tomnomnom/gf)                                                              | Wrapper around grep, to help you grep for things.                                | `pattern/scan`    |
| [gitleaks](https://github.com/gitleaks/gitleaks)                                                        | Tool for detecting secrets like passwords, API keys, and tokens in git repos, files, and stdin. | `secret/scan`     |
| [gospider](https://github.com/jaeles-project/gospider)                                                        | Fast web spider written in Go.                                                   | `url/crawl`       |
| [grype](https://github.com/anchore/grype)                                                           | Vulnerability scanner for container images and filesystems.                      | `vuln/scan`       |
| [h8mail](https://github.com/khast3x/h8mail)                                                          | Email information and password lookup tool.                                      | `user/recon/email` |
| [httpx](https://github.com/projectdiscovery/httpx)                                                           | Fast and multi-purpose HTTP toolkit.                                             | `url/probe`       |
| [katana](https://github.com/projectdiscovery/katana)                                                          | Next-generation crawling and spidering framework.                                | `url/crawl`       |
| [maigret](https://github.com/soxoj/maigret)                                                         | Collect a dossier on a person by username.                                       | `user/recon/username` |
| [mapcidr](https://github.com/projectdiscovery/mapcidr)                                                         | Utility program to perform multiple operations for a given subnet/cidr ranges.   | `ip/recon`        |
| [msfconsole](https://docs.rapid7.com/metasploit/msf-overview/)                                                      | CLI to access and work with the Metasploit Framework.                            | `exploit/attack`  |
| [naabu](https://github.com/projectdiscovery/naabu)                                                           | Port scanning tool written in Go.                                                | `port/scan`       |
| [nmap](https://github.com/nmap/nmap)                                                            | Network Mapper is a free and open source utility for network discovery and security auditing. | `port/scan`       |
| [nuclei](https://github.com/projectdiscovery/nuclei)                                                          | Fast and customisable vulnerability scanner based on simple YAML based DSL.      | `vuln/scan`       |
| [searchsploit](https://gitlab.com/exploit-database/exploitdb)                                                    | Exploit searcher based on ExploitDB.                                             | `exploit/recon`   |
| [subfinder](https://github.com/projectdiscovery/subfinder)                                                       | Fast passive subdomain enumeration tool.                                         | `dns/recon`       |
| [testssl](https://github.com/testssl/testssl.sh)                                                         | SSL/TLS security scanner, including ciphers, protocols and cryptographic flaws.  | `dns/recon/tls`   |
| [trivy](https://github.com/aquasecurity/trivy)                                                           | Comprehensive and versatile security scanner.                                    | `vuln/scan`       |
| [wafw00f](https://github.com/EnableSecurity/wafw00f)                                                         | Web Application Firewall Fingerprinting tool.                                    | `waf/scan`        |
| [wpprobe](https://github.com/Chocapikk/wpprobe)                                                         | Fast wordpress plugin enumeration tool.                                          | `vuln/scan/wordpress` |
| [wpscan](https://github.com/wpscanteam/wpscan)                                                          | Wordpress security scanner.                                                      | `vuln/scan/wordpress` |
<!-- END_TOOLS_TABLE -->

Feel free to request new tools to be added by opening an issue, but please 
check that the tool complies with our selection criterias before doing so. If it doesn't but you still want to integrate it into `secator`, you can plug it in (see the [dev guide](https://docs.freelabz.com/for-developers/writing-custom-tasks)).


## Installation

### Installing secator

<details>
    <summary>Pipx</summary>

```sh
pipx install secator
```
***Note:** Make sure to have [pipx](https://pipx.pypa.io/stable/installation/) installed.*

</details>

<details>
    <summary>Pip</summary>

```sh
pip install secator
```

</details>

<details>
  <summary>Bash (uses apt)</summary>

```sh
wget -O - https://raw.githubusercontent.com/freelabz/secator/main/scripts/install.sh | sh
```

</details>

<details>
    <summary>Docker</summary>

```sh
docker run -it --rm --net=host -v ~/.secator:/root/.secator freelabz/secator --help
```

The volume mount -v is necessary to save all secator reports to your host machine, and--net=host is recommended to grant full access to the host network.

You can alias this command to run it easier:
```sh
alias secator="docker run -it --rm --net=host -v ~/.secator:/root/.secator freelabz/secator"
```

Now you can run secator like if it was installed on baremetal:
```
secator --help
```

</details>

<details>
    <summary>Docker Compose</summary>

```sh
git clone https://github.com/freelabz/secator
cd secator
docker-compose up -d
docker-compose exec secator-client secator --help
```

</details>

***Note:*** If you chose the Bash, Docker or Docker Compose installation methods, you can skip the next sections and go straight to [Usage](#usage).

### Installing languages

`secator` uses external tools, so you might need to install languages used by those tools assuming they are not already installed on your system.

We provide utilities to install required languages if you don't manage them externally:

<details>
    <summary>Go</summary>

```sh
secator install langs go
```

</details>

<details>
    <summary>Ruby</summary>

```sh
secator install langs ruby
```

</details>

### Installing tools

`secator` does not install any of the external tools it supports by default.

We provide utilities to install or update each supported tool which should work on all systems supporting `apt`:

<details>
    <summary>All tools</summary>

```sh
secator install tools
```

</details>

<details>
    <summary>Specific tools</summary>

```sh
secator install tools <TOOL_NAME>
```

For instance, to install `httpx`, use:

```sh
secator install tools httpx
```

</details>

Please make sure you are using the latest available versions for each tool before you run secator or you might run into parsing / formatting issues.

### Installing addons

`secator` comes installed with the minimum amount of dependencies.

There are several addons available for `secator`:

<details>
    <summary>worker</summary>

Add support for Celery workers (see [Distributed runs with Celery](https://docs.freelabz.com/in-depth/distributed-runs-with-celery)).
```sh
secator install addons worker
```

</details>


<details>
    <summary>gdrive</summary>

Add support for Google Drive exporter (`-o gdrive`).

```sh
secator install addons gdrive
```

</details>

<details>
    <summary>gcs</summary>

Add support for Google Cloud Storage driver (`-driver gcs`).

```sh
secator install addons gcs
```

</details>

<details>
    <summary>mongodb</summary>

Add support for MongoDB driver (`-driver mongodb`).
```sh
secator install addons mongodb
```

</details>

<details>
    <summary>redis</summary>

Add support for Redis backend (Celery).

```sh
secator install addons redis
```

</details>

<details>
    <summary>dev</summary>

Add development tools like `coverage` and `flake8` required for running tests.

```sh
secator install addons dev
```

</details>

<details>
    <summary>trace</summary>

Add tracing tools like `memray` and `pyinstrument` required for tracing functions.

```sh
secator install addons trace
```

</details>

<details>
    <summary>build</summary>

Add `hatch` for building and publishing the PyPI package.

```sh
secator install addons build
```

</details>


### Checking installation health

To figure out which languages or tools are installed on your system (along with their version):
```sh
secator health
```

## Usage
```sh
secator --help
```
![](images/help.png)


### Usage examples

Run a fuzzing task (`ffuf`):

```sh
secator x ffuf http://testphp.vulnweb.com/FUZZ
```

Run a url crawl workflow:

```sh
secator w url_crawl http://testphp.vulnweb.com
```

Run a host scan:

```sh
secator s host mydomain.com
```

and more... to list all tasks / workflows / scans that you can use:
```sh
secator x --help
secator w --help
secator s --help
```

## Learn more

To go deeper with `secator`, check out:
* Our complete [documentation](https://docs.freelabz.com)
* Our getting started [tutorial video](https://youtu.be/-JmUTNWQDTQ?si=qpAClDWMXo2zwUK7)
* Our [Medium post](https://medium.com/p/09333f3d3682)
* Follow us on social media: [@freelabz](https://twitter.com/freelabz) on Twitter and [@FreeLabz](https://youtube.com/@FreeLabz) on YouTube

## Stats

<a href="https://star-history.com/#freelabz/secator&Date">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=freelabz/secator&type=Date&theme=dark" />
    <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=freelabz/secator&type=Date" />
    <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=freelabz/secator&type=Date" />
  </picture>
</a>
