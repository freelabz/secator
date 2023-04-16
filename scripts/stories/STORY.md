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
secsy worker & # run worker in background
secsy w url_fuzz mydomain.com # workflow will be run in background
```

### Proxy usage demo


### Demo aliases
```sh
secsy u enable-aliases
source ~/.secsy/.aliases
host_recon mydomain.com
```

### Feature-based demo

**Ad-hoc discovery:**

```sh
# pipe naabu and httpx to find all alive HTTP servers available on the host
secsy x naabu mydomain.com | secsy x httpx -mc 200 -table

# run a basic URL crawler workflow on the host to see which URLs are up
secsy w url_crawl mydomain.com

# fuzz one of the URLs to find more URLs 
secsy x ffuf https://mydomain.com/FUZZ -mc 200,301,400,500 -table | secsy x httpx -mc 200 -table

**Host scan:**
secsy w host_recon mydomain.com

**Subdomain mapping:**
secsy w subdomain_recon mydomain.com
secsy x subfinder mydomain.com | secsy x httpx -json -table | httpx -mc 200 -json -table

**Run in distributed mode:**
secsy z default mydomain.com --worker
```

**Callbacks (library mode):**
```py
from secsy.runners import Workflow
from secsy.config import ConfigLoader

config = ConfigLoader(name='workflows/host_recon')
callbacks = {
    'output': {
        Port: [save_port_to_db],
        Vulnerability: [save_vulnerability_to_db, send_vulnerability_to_discord],
    }
}
workflow = Workflow(config, callbacks=callbacks)
result = workflow.delay()
while not result.ready():
    nports = db.session.query(Vulnerability).count()
    nvulns = db.session.query(Ports).count()

all_results = result.get()
```