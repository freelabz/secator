import re

from secator.decorators import task
from secator.definitions import URL, DELAY, PROXY, THREADS, TIMEOUT, HEADER
from secator.output_types import Vulnerability
from secator.tasks._categories import VulnHttp

from urllib.parse import urlparse
import urllib.parse


@task()
class sqlmap(VulnHttp):
    """Automatic SQL injection and database takeover tool."""
    cmd = 'sqlmap'
    input_types = [URL]
    output_types = [Vulnerability]
    tags = ['sql', 'sqli', 'vulnerability', 'http', 'web']
    file_flag = '-m'
    input_flag = '-u'
    json_flag = None
    version_flag = '--version'
    opt_key_map = {
        HEADER: 'H',
        DELAY: 'delay',
        PROXY: 'proxy',
        TIMEOUT: 'timeout',
        THREADS: 'threads',
    }
    # sqlmap accepts proxy URLs with scheme e.g. http://, https://, socks5://
    opt_value_map = {}
    install_version = '1.8.9'
    install_cmd = 'pipx install "sqlmap==[install_version]"'
    github_handle = 'sqlmapproject/sqlmap'
    proxychains = False
    proxy_http = True
    proxy_socks5 = True
    profile = 'io'

    @staticmethod
    def on_cmd(self):
        # Ensure non-interactive behavior and sane defaults
        # --batch: never prompt for user input
        # --random-agent: use random User-Agent
        # --color=never: easier to parse output
        self.cmd += ' --batch'
        self.cmd += ' --random-agent'
        # self.cmd += ' --os-shell --dump-all --dbs --tables --columns --schema --comments'
        # self.cmd += ' -v 6'

    @staticmethod
    def on_start(self):
        # Internal parsing state
        self._sqlmap_state = {
            'dbms': None,
            'tech': None,
            'current_param': None,
            'current_type': None,
            'current_title': None,
            'current_payload': None,
        }

    @staticmethod
    def item_loader(self, line):
        # Normalize line
        s = line.strip()

        # Capture DBMS info
        m_dbms = re.search(r'(?i)\bback-end\s+DBMS:\s*(.+)$', s)
        if m_dbms:
            self._sqlmap_state['dbms'] = m_dbms.group(1).strip()

        # Capture web technology info
        m_tech = re.search(r'(?i)\bweb application technology:\s*(.+)$', s)
        if m_tech:
            self._sqlmap_state['tech'] = m_tech.group(1).strip()

        # Quick vulnerable indicator: "parameter 'id' is vulnerable"
        m_vuln = re.search(r"(?i)\bparameter\s+'([^']+)'\s+is\s+vulnerable", s)
        if m_vuln:
            param = m_vuln.group(1)
            name = 'SQL Injection'
            extra = {'evidence': s, 'param': param}
            dbms = self._sqlmap_state.get('dbms')
            if dbms:
                extra['dbms'] = dbms
            technology = self._sqlmap_state.get('tech')
            if technology:
                extra['technology'] = technology
            type = self._sqlmap_state.get('current_type')
            if type:
                name += ' - ' + type
                extra['type'] = type
            title = self._sqlmap_state.get('current_title')
            if title:
                name += ' - ' + title
                extra['title'] = title
            payload = self._sqlmap_state.get('current_payload')
            if payload:
                extra['payload'] = payload
            matched_at = getattr(self, 'current_input', None) or getattr(self, 'input', None) or self.inputs[0]
            matched_at = urlparse(matched_at).netloc + urlparse(matched_at).path
            payload_encoded = urllib.parse.quote(self._sqlmap_state['current_payload'])
            extra['evidence'] = 'curl ' + matched_at + ' -d "' + payload_encoded + '"'
            yield Vulnerability(
                name=name,
                matched_at=matched_at,
                severity='high',
                description='sqlmap detected a SQL injection vulnerability.',
                extra_data=extra
            )

        # Detailed block parsing when sqlmap prints injection point details:
        # Examples:
        #   Parameter: id (GET)
        #   Type: boolean-based blind
        #   Title: AND boolean-based blind - WHERE or HAVING clause
        #   Payload: id=1 AND 1234=1234
        m_param = re.match(r'(?i)^Parameter:\s*([^\s]+)', s)
        if m_param:
            self._sqlmap_state['current_param'] = m_param.group(1).strip()
            # Reset per-finding fields
            self._sqlmap_state['current_type'] = None
            self._sqlmap_state['current_title'] = None
            self._sqlmap_state['current_payload'] = None

        m_type = re.match(r'(?i)^Type:\s*(.+)', s)
        if m_type:
            self._sqlmap_state['current_type'] = m_type.group(1).strip()

        m_title = re.match(r'(?i)^Title:\s*(.+)', s)
        if m_title:
            self._sqlmap_state['current_title'] = m_title.group(1).strip()

        m_payload = re.match(r'(?i)^Payload:\s*(.+)', s)
        if m_payload:
            self._sqlmap_state['current_payload'] = m_payload.group(1).strip()
            name = 'SQL Injection'
            # When payload is printed, we have enough info to yield a finding
            extra = {'payload': self._sqlmap_state.get('current_payload'), 'param': self._sqlmap_state.get('current_param')}  # noqa: E501
            dbms = self._sqlmap_state.get('dbms')
            if dbms:
                extra['dbms'] = dbms
            technology = self._sqlmap_state.get('tech')
            if technology:
                extra['technology'] = technology
            type = self._sqlmap_state.get('current_type')
            if type:
                name += ' - ' + self._sqlmap_state.get('current_type')
                extra['type'] = type
            title = self._sqlmap_state.get('current_title')
            if title:
                name += ' - ' + self._sqlmap_state.get('current_title')
                extra['title'] = title
            payload = self._sqlmap_state.get('current_payload')
            if payload:
                extra['payload'] = payload
            matched_at = getattr(self, 'current_input', None) or getattr(self, 'input', None) or self.inputs[0]
            matched_at = urlparse(matched_at).netloc + urlparse(matched_at).path
            payload_encoded = urllib.parse.quote(self._sqlmap_state['current_payload'])
            extra['evidence'] = 'curl ' + matched_at + ' -d "' + payload_encoded + '"'
            yield Vulnerability(
                name=name,
                matched_at=matched_at,
                severity='high',
                description=self._sqlmap_state.get('current_title') or 'sqlmap detected a SQL injection vulnerability.',
                extra_data=extra
            )
