import click
import os
import yaml
import json

from secator.decorators import task
from secator.definitions import (OUTPUT_PATH)
from secator.output_types import Info
from secator.runners import Command
from secator.tasks._categories import OPTS
from secator.utils import process_wordlist


@task()
class enumdns(Command):
    """EnumDNS is a modular DNS reconnaissance tool capable of resolving hosts from various sources, 
    including wordlists, BloodHound files, and Active Directory environments."""
    cmd = 'enumdns'
    json_flag = '--write-jsonl'

    opt_prefix = '-'
    opts = {
		'mode': {'type': click.Choice(['recon', 'brute']), 'default': 'recon', 'help': 'Enumdns mode', 'internal': True, 'display': True},
        'd': {'type': str, 'help': 'Domain for enumeration'},
        'w': {'type': str, 'default': None, 'process': process_wordlist, 'help': 'Wordlist to use (default: enumedns wordlist)'}
	}
    
    install_version = 'v0.1.18'
    install_cmd = 'go install -v github.com/helviojunior/enumdns@[install_version]'
    install_github_handle = 'helviojunior/enumdns'
    
    @staticmethod
    def on_cmd_done(self):
        if not os.path.exists('enumdns.jsonl'):
            yield Error(message=f'Could not find JSON results in enumdns.jsonl')
            return

        yield Info(message=f'JSON results saved to enumdns.jsonl')
        results = []
        with open('enumdns.jsonl', 'r') as f:
            # parse line by line because is jsonl file
            for line in f.readlines():
                results.append(line.strip())
        
        for domain in results:
            yield Info(
				message=f"{json.loads(domain)['fqdn']}      {json.loads(domain)['result_type']}     {json.loads(domain)['ipv4']}"
			)