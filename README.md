# `secsy` - Sexy security swiss-knife

`secsy` is a sexy security **security swiss-knife** that wraps common
security-oriented commands in a single CLI.

`secsy` is designed to not waste your time and make you efficient at
vulnerability assessments, with the following feature set:

* **Curated list of commands**: commands integrated to `secsy` are carefully 
    chosen to be **fast**, **efficient**, **well-maintained**, and for the vast
    majority have **structured output** (either `JSON`, `JSON lines`, `CSV`, or
    `XML`) making it easier to build complex workflows (we do make exceptions
    and write custom parsers for really awesome tools that don't have it).

* **Unified input options**: commands belonging to the same category will have
    the same input options, while still retaining the capability to add specific
    command options.

* **Unified output schema**: commands belonging to the same category will have a
    unified output schema, allowing you to run multiple commands and aggregate
    results quickly.

* **CLI and library usage**:
    * When `secsy` is called as a library from other Python code, the output is
    always structured (list of dicts). Results are also yielded in realtime.
    * When `secsy` is called as a CLI, various output formats are available,
    such as `plaintext` (default), `json` (`jq` compatible), `raw` (pipeable
    to other commands) or `table` (nice to look at).

* **Distributed options**:
    * By default, `secsy` will work in synchronous mode in both CLI and library
    modes.
    * When you want to increase the scanning speed you can run in distributed
    mode, where you can easily configure task queues with Celery by configuring
    your broker and results backend.

* **From simple tasks to complex workflows**:
    * You can use `secsy` to run simple tasks like in CTFs, bug-bounties or 
    hackathon, or to automate your whole recon and pentesting workflows.

* **Customizable**:
    * You can add more supported commands to `secsy` in a breeze (ad-hoc 
    plugins), and contribute them back to the repo if they can serve the greater
    good.
    * You can create endless workflows with pretty much as much complexity as 
    you like.


## Supported commands

`secsy` integrates the following commands: 

**HTTP:**
* [cariddi](https://github.com/edoardottt/cariddi) - Fast crawler and endpoint
/ secrets / api keys / tokens matcher.
* [dirsearch](https://github.com/maurosoria/dirsearch) - Web path discovery.
* [feroxbuster](https://github.com/epi052/feroxbuster) - Simple, fast, recursive
content discovery tool written in Rust.
* [ffuf](https://github.com/ffuf/ffuf) - Fast web fuzzer written in Go.
* [gau](https://github.com/lc/gau): Offline URL crawler (Alien Vault, The
Wayback Machine, Common Crawl, URLScan).
* [gospider](https://github.com/jaeles-project/gospider) - Fast web spider
written in Go.
* [httpx](https://github.com/projectdiscovery/httpx) - Fast HTTP prober.
* [katana](https://github.com/projectdiscovery/katana) - Next-generation
crawling and spidering framework.

**Misc:**
* [gf](https://github.com/tomnomnom/gf) - A wrapper around grep to avoid typing common patterns.
* [msfconsole](https://docs.rapid7.com/metasploit/msf-overview) - CLI to access
and work with the Metasploit Framework.

**Recon:**
* [fping](https://fping.org/) - Find alive hosts on local networks.
* [maigret](https://github.com/soxoj/maigret) - Hunt for user accounts across many websites.
* [mapcidr](https://github.com/projectdiscovery/mapcidr) - Expand CIDR ranges into IPs.
* [naabu](https://github.com/projectdiscovery/naabu) - Fast port discovery tool.
* [subfinder](https://github.com/projectdiscovery/subfinder) - Fast subdomain finder.

**Vulnerabilities:**
* [dalfox](https://github.com/hahwul/dalfox) - Powerful XSS scanning tool and parameter analyzer.
* [grype](https://github.com/anchore/grype) - A vulnerability scanner for container images and filesystems.
* [nmap](https://github.com/nmap/nmap) - Vulnerability scanner using NSE scripts.
* [nuclei](https://github.com/projectdiscovery/nuclei) - Fast and customisable vulnerability scanner based on simple YAML based DSL.

Feel free to request new commands to be added by opening an issue, but please 
check that the command complies with our selection criterias before doing so. If it doesn't but you still want to integrate it into `secsy`, you can plug it in (see the [dev guide](#Developer-guide)).

## Requirements

* go
* python3
* pip3

## Installation

<!-- `pip3 install secsy` -->
```sh
git clone https://github.com/ocervell/secsy-cli
cd secsy-cli
python3 -m virtualenv -p python3 ~/.virtualenv/secsy
pip3 install -e .
```

## CLI Usage

### Usage

```sh
secsy --help
```

#### Tasks

Run any of the supported commands out-of-the box using the `secsy task` subcommand:

```sh
secsy task --help # list available commands
secsy task <COMMAND> --help # list command options
```

#### Workflows

A workflow is a set of pre-defined tasks.

You can run some pre-written workflows using the `secsy workflow` subcommand:

```sh
secsy workflow --help # list available workflows
secsy workflow <NAME> --help # list workflow options
```

* **Basic host recon** (open ports, network + HTTP vulnerabilities):
    ```sh
    secsy workflow host_recon 192.168.1.18
    ```

* **Basic subdomain recon** (subdomains, root URLs):
    ```sh
    secsy workflow subdomain_recon mydomain.com
    ```

* **Basic URL crawler:**
    ```sh
    secsy workflow url_crawler https://mydomain.com/start/crawling/from/here/
    ```

* **Basic URL fuzzer:**
    ```sh
    secsy workflow url_fuzzer https://mydomain.com/start/fuzzing/from/here/
    ```

* **Internal CIDR recon:**
    ```sh
    secsy workflow cidr_recon 192.168.0.1/24
    ```

* **Code scan:**
    ```sh
    secsy workflow code_scan /path/to/code/repo
    ```


#### Scans

A scan is a set of workflows that run one after the other.

You can run some pre-written scans using the `secsy scan` subcommand:

```sh
secsy scan --help # list available scans
secsy scan <NAME> --help # list scan options
```

* **Domain scan**:
    ```sh
    secsy scan domain example.com
    ```

* **Network scan**:
    ```sh
    secsy scan network 192.168.1.0/24
    ```

### Input options

The `secsy` CLI is built to be flexible in terms of inputs:

**Direct input**

Input can be passed directly as an argument to the command / workflow / scan you 
wish to run:

```sh
secsy task httpx example.com # single input
secsy task httpx example.com,example2.com,example3.com # multiple inputs
```

**File input**

Input can also be passed from a file containing one item per line:

```sh
secsy task httpx urls.txt
```

**Stdin input**

Input can also be passed directly from stdin, which in combination with the 
`--raw --json` switch allows to build workflows directly in the CLI:

```sh
cat urls.txt | secsy task httpx
```

An example for a common **ProjectDiscovery** pipe:

```sh
secsy task subfinder example.com --raw --json | secsy task httpx --raw --json | secsy task nuclei
```

***Note:*** *for more complex workflows, we highly recommend using the YAML-based
workflow definitions or the code-based workflow definitions.*

### Output options

The `secsy` CLI is built to be very flexible in terms of output formats:
- `-json` for JSONLines output
- `-json -color` for nicely formatted JSONLines output (`jq` style)
- `-table` for nicely formatted table output
- `-raw` for plaintext output (used for piping into other tools)

If none of these options are passed, the command output will be the original 
output.

<!-- ![](images/formatting_httpx.gif) -->
![](images/formatting_ffuf.gif)

## Library usage

**Using a command as a generator**

Since some commands return results live, we can run them as a generator by 
simply calling them in a `for` loop like, and consume results lazily with e.g a 
Celery task.

```py
from secsy.tasks.http import ffuf

app = Celery(__name__)

@app.task
def process_ffuf_item(result):
    Results.objects.create(**result)

host = 'wikipedia.org'
for result in ffuf(host):
    process_ffuf_item.delay(result)
```

***Note:*** all commands support being run like generators, even if some of them
wait for command to finish before outputting results (e.g: `nmap`).

**Options override**

Options specified with the name of the command name prefixed will override 
global options for that specific command.

For instance, if you want a global rate limit of `1000` (reqs/s), but for ffuf you want it 
to be `100` you can do so:

```py
from secsy.tasks.http import ffuf, gau, gospider, katana
host = 'wikipedia.org'
options = {
    'rate_limit': 1000, # reqs/mn
    'ffuf_rate_limit': 100,
    'katana_rate_limit': 30
}
for tool in [ffuf, gau, gospider, katana]:
    tool(host, **options)

for result in ffuf(host, wordlist='/usr/src/wordlist/dicc.txt'):
    print(result)
```

In the example above:

* `gau`, and `gospider` will have a rate limit of `1000` 
requests / minute.
* `ffuf` will have a rate limit of `100` requests / minute.
* `katana` will have a rate limit of `30` requests / minute.


**Disabling default options:**

Sometimes you might wish to omit passing the option and use the command 
defaults. You can set the option to `False` in order to do this.

```py
options = {
    'rate_limit': 1000, # reqs/mn
    'ffuf_rate_limit': False, # explicitely disabling `rate_limit` option, will use ffuf defaults
}
```

**Examples:**

***Find subdomains using `subfinder` and run HTTP probe using `httpx` on found subdomains***
```py
from secsy.tasks.recon import subfinder
from secsy.tasks.http import httpx

host = 'alibaba.com'
subdomains = subfinder(host, threads=30, raw=True).run()
probes = httpx(subdomains).run()
for probe in probes:
    print('Found alive subdomain URL {url}[{status_code}]'.format(**probe))
```

***Find open ports and run `nmap`'s `vulscan` NSE script on results***

```py
from secsy.tasks.recon import naabu
from secsy.tasks.vuln import nmap

host = 'cnn.com'
ports_data = naabu(host).run()
ports = [p['port'] for p in ports_data]
print(f'Open ports: {ports}')
for port in ports:
    vulns = nmap(host, ports=ports, script='vulscan').run()
```

***Finding URLs***

```py
from secsy.utils import setup_logger
from secsy.tasks.http import httpx, ffuf, gau, gospider, katana
host = 'example.com'
opts = {
    'match_codes': '200, 302',
    'timeout': 3,
    'table': True,
    'quiet': True,
    'ffuf_wordlist': '/usr/src/wordlist/dicc.txt' # ffuf wordlist
}

# Setup a logger to see command output in console
setup_logger(level='debug', format='%(message)s')

# Probe initial host and get only the first URL using `first()`
# Since a host is considered alive no matter which status code it returns,
# we override the match_codes global option using the prefixed version.
url = httpx(host, raw=True, httpx_match_codes='', **opts).first()

# Gather URLs
all_urls = []
for tool in [gospider, katana, ffuf, gau]
    urls = tool(url, **opts)
    all_urls.extend(urls)
print(f'Found {len(all_urls)} URLs while scraping {host} !')

# Probe URLs with httpx
all_urls = httpx(all_urls, **opts).run()

print(f'Found {len(probed_urls)} alive URLs while scraping {host} !')
```

## Distributed runs

By default, `secsy` runs all tasks synchronously. You can set up a task queue 
using Celery with the broker and a results backend of your choice, and run 
Celery workers to execute tasks from the broker queue.

The following is an example using `redis`, but you can use any [supported Celery 
broker and backend](https://docs.celeryq.dev/en/stable/getting-started/backends-and-brokers/index.html).

**Install `redis`:**

```sh
sudo apt install redis
```

**Start `redis` and enable at boot:**
```sh
sudo systemctl enable redis
sudo systemctl start redis
```

**Configure `secsy` to use Redis:**

Create a `.env` file in the directory where you run `secsy`, and fill it like so:
```sh
CELERY_BROKER_URL = 'redis://localhost:6379/0'
CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'
```

**Start a Celery worker:**

```sh
secsy worker
```

**Run a built-in workflow:**

```sh
secsy workflow host_scan wikipedia.org
```

**Note:** If you want to run a workflow synchronously (bypassing the broker) 
for some reason, you can use the `--sync` flag to force it to run synchronously.

**Run a built-in workflow from Python:**

```py
from secsy.runners import Workflow
from secsy.config import ConfigLoader

config = ConfigLoader(name='host_scan')
workflow = Workflow(config)
results = workflow.run()
print(results)
```

**Run a custom workflow from Python:**

```py
from secsy.runners import Workflow
from secsy.config import COnfigLoader

config = ConfigLoader(path='/path/to/my/custom/workflow.yaml')
workflow = Workflow(config)
results = workflow.run()
print(results)
```

## Developer guide

If you wish to integrate a new command with `secsy`, you can define a new class
inherited from `secsy.runners.Command`.

### Example

Let's suppose we have a **fictional** utility called `bigdog` which purpose is 
to hunt cats on the internet.


`bigdog` can be run on a single host or domain using `-site`:
```sh
$ bigdog -site loadsofcats.com
   / \__
  (    @\___   =============
  /         O  BIGDOG v1.0.0
 /   (_____/   =============
/_____/
garfield [boss, 14]
tony [admin, 18]
```

`bigdog` can output JSON lines using `-json`:
```sh
$ bigdog -site loadsofcats.com -json
   / \__
  (    @\___   =============
  /         O  BIGDOG v1.0.0
 /   (_____/   =============
/_____/
{"name": "garfield", "age": 14, "host": "loadsofcat.com", "position": "boss"}
{"name": "tony", "age": 18, "host": "loadsofcats.com", "position": "admin"}
```

`bigdog` can also be called on a list of sites stored in a file using `-list`:

```sh
$ bigdog -list sites.txt -json
   / \__
  (    @\___   =============
  /         O  BIGDOG v1.0.0
 /   (_____/   =============
/_____/
{"name": "garfield", "age": 14, "host": "loadsofcat.com", "position": "boss"}
{"name": "romuald", "age": 5, "host": "cathistory.com", "position": "minion"}
{"name": "tony", "age": 18, "host": "loadsofcats.com", "position": "admin"}
```


A basic definition of `bigdog` using basic `secsy` concepts will be:

```py
from secsy.runners import Command

class bigdog(Command):
    cmd = 'bigdog'
    json_flag = '-json'    
    input_flag = '-site'
    file_flag = '-list'
```

By defining the class above in a `test.py` file, you can now run `bigdog` from
code with either of the following methods:

```py
>>> from test import bigdog

# Get all results as a list, blocks until command has finished running
>>> bigdog('loadsofcats.com').run()
[
    {"name": "garfield", "age": 14, "host": "loadofcats.com", "position": "boss"},
    {"name": "tony", "age": 18, "host": "loadsofcats.com", "position": "admin"}
]

# Get result items in real-time as they arrive to stdout
>>> for cat in bigdog('loadsofcats.com'):
>>> ... print(cat['name'] + '(' + cat['age'] + ')')
garfield (14)
tony (18)

# Get only the result item, and kills the command upon receiving it. 
# This can be useful for some commands where you don't want to wait for the full 
# command to execute
>>> bigdog('loadsofcats.com').first()
{"name": "garfield", "age": 14, "host": "loadsofcats.com", "position": "boss"}
```

Okay, this is a good start.

Now what if the `bigdog` command has some more options that you would like to
integrate ?

For instance:
* `-timeout` allows to specify a request timeout.
* `-rate` allows to specify the max requests per minute.

You can add the `opts` parameter to your `Command` object to define the
cmd options:

```py
from secsy.runners import Command

class bigdog(Command):
    cmd = 'bigdog'
    json_flag = '-json'
    input_flag = '-site'
    file_flag = '-list'
    opt_prefix = '-'
    opts = {
        'timeout': {'type': int, 'help': 'Timeout (in seconds)'},
        'rate': {'type': int, 'help': 'Max requests per minute'}
    }
```

You can register this command with Click by adding it to the list 
`secsy.cli.ALL_CMDS`, and then use it from the CLI:

```
secsy task bigdog --help
secsy task bigdog loadsofcats.com
secsy task bigdog loadsofcats.com -timeout 1 -rate 100 -json
```

Note that as CLI options defined in the class are automatically added to the 
corresponding CLI command, as well as some useful formatting options:

* **Table output** (`-table`)
    ```sh
    $ secsy task bigdog loadsofcats.com -table
        / \__
       (    @\___  =============
      /         O  BIGDOG v1.0.0
     /   (_____/   =============
    /_____/
    ╒══════════╤═══════╤═════════════════╤════════════╕
    │ Name     │   Age │ Host            │ Position   │
    ╞══════════╪═══════╪═════════════════╪════════════╡
    │ garfield │    14 │ loadofcats.com  │ boss       │
    ├──────────┼───────┼─────────────────┼────────────┤
    │ tony     │    18 │ loadsofcats.com │ admin      │
    ╘══════════╧═══════╧═════════════════╧════════════╛
    ```

* **JSON Lines output** (`-json`)
    ```sh
    $ secsy task bigdog loadsofcats.com -json
        / \__
       (    @\___  =============
      /         O  BIGDOG v1.0.0
     /   (_____/   =============
    /_____/
    {"name": "garfield", "age": 14, "host": "loadofcats.com", "position": "boss", "_source": "bigdog"}
    {"name": "tony", "age": 18, "host": "loadsofcats.com", "position": "admin", "_source": "bigdog"}
    ```

* **Quiet mode** (`-quiet`)
    ```sh
    $ secsy task bigdog loadsofcats.com -quiet
    ```

### Advanced example

One advantage of having class-based definition is that we can group similar
tools together.

For instance, we could have a class of "cat-hunting tools" that defines some
options similar to all tools hunting cats.

Let's assume we have 2 other tools that can hunt cats: `catkiller` and `eagle`...

... but each of those tools might be written by a different person, and so the
interface and output is different for all of them:

**`catkiller`**

```sh
$ catkiller --host loadsofcats.com --max-wait 1000 --max-rate 10 --json
Starting catkiller session ...
{"_info": {"name": "tony", "years": 18}, "site": "loadsofcats.com", "job": "admin"}
{"_info": {"name": "garfield", "years": 14}, "site": "loadsofcats.com", "job": "boss"}

# or to pass multiple hosts, it needs to be called like:
$ cat hosts.txt | catkiller --max-wait 1000 --max-rate 10 --json
```

***Inputs:***
* `--host` option is the same as `bigdog`'s `-site` option.
* `--max-wait` option is the same as `bigdog`'s `-timeout` option, but in milliseconds instead of seconds.
* `--max-rate` option is the same as `bigdog`'s `-rate` option, but has a different name.
* `--json` option is the same as `bigdog's` `-json` option, but uses a different option character "`--`".
* `cat hosts.txt | catkiller` is the equivalent to our `bigdog`'s `-list` option.

***Output:***
* `_info` has the data for `name` and `age`, but `age` is now `years`.
* `site` is the equivalent of `bigdog`'s `host`.
* `job` is the equivalent of `bigdog`'s `position`.


**`eagle`**
```sh
$ eagle -u loadsofcats.com -timeexpires 1 -jsonl
                  _      
                 | |     
  ___  __ _  __ _| | ___ 
 / _ \/ _` |/ _` | |/ _ \
|  __/ (_| | (_| | |  __/  v2.2.0
 \___|\__,_|\__, |_|\___|
             __/ |       
            |___/       
{"alias": "tony", "occupation": "admin", "human_age": 105}

# or to pass multiple hosts, it needs to be called like:
$ eagle -l hosts.txt -timeexpires 1 -jsonl
                  _      
                 | |     
  ___  __ _  __ _| | ___ 
 / _ \/ _` |/ _` | |/ _ \
|  __/ (_| | (_| | |  __/  v2.2.0
 \___|\__,_|\__, |_|\___|
             __/ |       
            |___/    
{"alias": "tony", "occupation": "admin", "human_age": 105, "host": "loadsofcats.com"}
```

***Inputs:***
* `-u` is the same as `bigdog`'s `-site` option.
* `-l` is the same as `bigdog`'s `-list` option.
* `-timeexpires` is the same as `bigdog`'s `-timeout` option.
* `eagle` **does not support** setting the maximum requests per seconds (`bigdog`'s `-rate` option).
* `-jsonl` is the flag to output JSON lines, instead of `bigdog`'s `-json`.

***Output:***
* `alias` is the equivalent of `bigdog`'s `name`.
* `occupation` is the equivalent of `bigdog`'s `job`.
* `human_age` is the human age conversion of the cat age.

We want to uniformize all those tools options so that we can use them with the
same options set and they would return an output with the same schema.

To do so, we define a base class with the wanted interface and the meta options,
i.e options that are common to all tools; the wanted output schema, and the
conversion from the current output fields to the desired output schema.

We take `bigdog`'s options and output schema as reference, and modify the two
new commands to match those:

```py
from secsy.definitions import OPT_NOT_SUPPORTED


class CatHunter(Command):
    meta_opts = {
        'timeout': {'type': int, 'default': 1, 'help': 'Timeout (in seconds)'},
        'rate': {'type': int, 'default': 1000, 'help': 'Max requests per minute'},
    }
    output_schema = ['name', 'age', 'host', 'position']


class bigdog(CatHunter):
    cmd = 'bigdog'
    json_flag = '-json'
    input_flag = '-site'
    file_flag = '-list'
    opt_prefix = '-'


class catkiller(CatHunter):
    cmd = 'catkiller'
    json_flag = '--json'
    input_flag = '--host'

    # stdin-like input using 'cat <FILE> | <COMMAND>'
    file_flag = None

    # catkiller options start with "--" unlike the other tools
    opt_prefix = '--' 

    # Map `catkiller` options to CatHunter.meta_opts
    # secsy cmd catkiller loadsofcats.com --max-wait 1000 --max-rate 10 --json
    # will become
    # secsy cmd catkiller loadsofcats.com -timeout 1 -rate 10 -json
    opt_keys = {
        'rate': 'max-rate'
        'timeout': 'max-wait'
    }
    opt_values = {
        'timeout': lambda x: x / 1000 # converting milliseconds to seconds
    }

    # Here we map the `catkiller` output schema to CatHunter.output_schema:
    # {"_info": {"name": "tony", "years": 18}, "site": "loadsofcats.com", "job": "admin"}
    # will become
    # {"name": "tony", "age": 18, "host": "loadsofcats.com", "job": "admin"}
    output_map = {
        'name': lambda x: x['_info']['name'], # note: you can use any function, we use
        'age': lambda x: x['_info']['age'],   #       lambdas for readability here
        'host': 'site',   # 1:1 mapping
        'position': 'job' # 1:1 mapping
    }


class eagle(CatHunter):
    cmd = 'eagle'
    json_flag = '-jsonl'
    input_flag = '-u'
    file_flag = '-l'
    opt_keys = {
        'rate': 'timeexpires',
        'timeout': OPT_NOT_SUPPORTED # explicitely state that this option not supported by the target tool
    }

    # Here we map the `eagle` output schema to CatHunter.output_schema:
    # {"alias": "tony", "occupation": "admin", "human_age": 88}
    # will become
    # {"name": "tony", "age": 18, "host": "loadsofcats.com", "job": "admin"}
    output_map = {
        'name': 'alias',
        'age': lambda x: human_to_cat_age(x['human_age']),
        'job': 'occupation',
    }

    # Here we add the 'host' key dynamically after the item has been converted 
    # to the output schema, since `eagle` doesn't return the host systematically.
    def on_item_convert(self, item):
        item['host'] = item.get('host') or self.input
        return item


def human_to_cat_age(human_age):
    cat_age = 0
    if human_age <= 22:
        cat_age = human_age // 11
    else:
        cat_age = (human_age - 22) // 5 + 2
    return cat_age
```

Using those definitions, we can now use the commands with a common interface
(input options & output schema):

```py
>>> from test import bigdog, catkiller, eagle
>>> meta_opts = {'timeout': 1, 'rate': 1000}
>>> bigdog('loadsofcats.com', **meta_opts).run()
[
    {"name": "garfield", "age": 14, "host": "loadsofcats.com", "position": "boss", "_source": "bigdog"},
    {"name": "tony", "age": 18, "host": "loadsofcats.com", "position": "admin", "_source": "bigdog"}
]
>>> catkiller('catrunner.com', **meta_opts).run()
[
    {"name": "fred", "age": 12, "host": "catrunner.com", "position": "minion", "_source": "catkiller"},
    {"name": "mark", "age": 20, "host": "catrunner.com", "position": "minion", "_source": "catkiller"}
]
>>> eagle('allthecats.com', **meta_opts).run()
[
    {"name": "marcus", "age": 4, "host": "allthecats.com", "position": "minion", "_source": "eagle"},
    {"name": "rafik", "age": 7, "host": "allthecats.com", "position": "minion", "_source": "eagle"}
]
```

This means you can have a unified output for all those commands, and run all of
them in a loop, calling them with the same options:

```py
>>> from test import bigdog, catkiller, eagle
>>> from secsy.utils import fmt_table
>>> data = []
>>> for command in [bigdog, catkiller, eagle]:
>>> ... items = command(host, **meta_opts).run()
>>> ... data.extend(items)
>>> data
[{'name': 'garfield', 'age': 14, 'host': 'loadsofcats.com', 'position': 'boss', '_source': 'bigdog'}, {'name': 'tony', 'age': 18, 'host': 'loadsofcats.com', 'position': 'admin', '_source': 'bigdog'}, {'name': 'fred', 'age': 12, 'host': 'catrunner.com', 'position': 'minion', '_source': 'catkiller'}, {'name': 'mark', 'age': 20, 'host': 'catrunner.com', 'position': 'minion', '_source': 'catkiller'}, {'name': 'marcus', 'age': 4, 'host': 'allthecats.com', 'position': 'minion', '_source': 'eagle'}, {'name': 'rafik', 'age': 7, 'host': 'allthecats.com', 'position': 'minion', '_source': 'eagle'}]
>>> print(fmt_table(data, sort_by='age'))
╒══════════╤═══════╤═════════════════╤════════════╤════════════╕
│ Name     │   Age │ Host            │ Position   │  source    │
╞══════════╪═══════╪═════════════════╪════════════╪════════════╡
│ marcus   │     4 │ allthecats.com  │ minion     │  eagle     │
├──────────┼───────┼─────────────────┼────────────┼────────────┤
│ rafik    │     7 │ allthecats.com  │ minion     │  eagle     │
├──────────┼───────┼─────────────────┼────────────┼────────────┤
│ fred     │    12 │ catrunner.com   │ minion     │  catkiller │
├──────────┼───────┼─────────────────┼────────────┼────────────┤
│ garfield │    14 │ loadsofcats.com │ boss       │  bigdog    │
├──────────┼───────┼─────────────────┼────────────┼────────────┤
│ tony     │    18 │ loadsofcats.com │ admin      │  bigdog    │
├──────────┼───────┼─────────────────┼────────────┼────────────┤
│ mark     │    20 │ catrunner.com   │ minion     │  catkiller │
╘══════════╧═══════╧═════════════════╧════════════╧════════════╛
```

If you register these commands in the CLI, you can now call these commands using
`secsy`:

```sh
$ secsy cmd bigdog loadsofcats.com -rate 1000 -timeout 1 -json
$ secsy cmd eagle loadsofcats.com -rate 1000 -timeout 1 -json
$ secsy cmd catkiller loadsofcats.com -rate 1000 -timeout 1 -json
```


### Additional options

There are additional class options and functions you can specify in the
`Command` objects to customize the command running lifecycle and output
format:

* `opts` (`dict`, `default: {}`):

    Command options.

* `output_field` (`str`, `default: None`):

    Return this field when specifying `--raw` to the CLI. 
    Can be used to forward output to other tools.

* `shell` (`bool`, `default: False`):

    Run `subprocess.Popen` with `shell=True` (dangerous).

* `cwd` (`str`, `default: None`):
    
    Command current working directory.

* `encoding` (`dict`, `default: utf-8`):

    Output encoding.

* `json_output` (`bool`, `default: True`):

    Support JSON output.

* `def on_item(self, item)`:

    Callback to modify item with original schema. Must return the item.

* `def on_item_converted(self, item)`:

    Callback to modify item with the target schema defined by `self.output_schema`. Must return the item.

* `def on_line(self, line)`:

    Callback to modify line. Must return the line.

* `def on_start(self)`:

    Callback to do something before the command has started running.

* `def on_end(self)`:

    Callback to do something after the command has finished running.

* `def keep_item(self, item)`:

    Returns True if item needs to be kept (yielded), or False if item can be 
    skipped.

* `def item_loader(self, line)`:

    Load a line as dictionary.