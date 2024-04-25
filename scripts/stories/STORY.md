## Scenarios

### Short demo
```
./docs/stories/short_demo.sh
```

### Options format demo

```sh
./docs/stories/fmt.sh
```

### Input options demo
```sh
./docs/stories/input.sh
```

### Worker demo
```sh
secator worker & # run worker in background
secator w url_fuzz mydomain.com # workflow will be run in background
```

### Proxy usage demo


### Demo aliases
```sh
secator u enable-aliases
source ~/.secator/.aliases
host_recon mydomain.com
```

### Feature-based demo

**Ad-hoc discovery:**

```sh
# pipe naabu and httpx to find all alive HTTP servers available on the host
secator x naabu mydomain.com | secator x httpx -mc 200 -o table

# run a basic URL crawler workflow on the host to see which URLs are up
secator w url_crawl mydomain.com

# fuzz one of the URLs to find more URLs 
secator x ffuf https://mydomain.com/FUZZ -mc 200,301,400,500 -o table | secator x httpx -mc 200 -o table

**Host scan:**
secator w host_recon mydomain.com

**Subdomain mapping:**
secator w subdomain_recon mydomain.com
secator x subfinder mydomain.com | secator x httpx -json -o table | httpx -mc 200 -json -o table

**Run in distributed mode:**
secator z default mydomain.com --worker
```

**Callbacks (library mode):**
```py
from secator.runners import Workflow
from secator.template import TemplateLoader

config = TemplateLoader(name='workflows/host_recon')
hooks = {
	Task: {
		'on_item': {
			Port: [save_port_to_db],
			Vulnerability: [save_vulnerability_to_db, send_vulnerability_to_discord],
		}
	}
}
workflow = Workflow(config, hooks=hooks)
result = workflow.delay()
while not result.ready():
    nports = db.session.query(Vulnerability).count()
    nvulns = db.session.query(Ports).count()

all_results = result.get()
```