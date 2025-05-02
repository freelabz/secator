import json
import os
from datetime import datetime

from secator.config import CONFIG
from secator.decorators import task
from secator.output_types import Vulnerability, Certificate, Error, Info, Ip, Tag
from secator.definitions import (PROXY, HOST, USER_AGENT, HEADER, OUTPUT_PATH,
                                CERTIFICATE_STATUS_UNKNOWN, CERTIFICATE_STATUS_TRUSTED, CERTIFICATE_STATUS_REVOKED,
                                TIMEOUT)
from secator.tasks._categories import Command, OPTS


@task()
class testssl(Command):
    """SSL/TLS security scanner, including ciphers, protocols and cryptographic flaws."""
    cmd = 'testssl.sh'
    tags = ['dns', 'recon', 'tls']
    input_types = [HOST]
    input_flag = None
    file_flag = '-iL'
    file_eof_newline = True
    version_flag = ''
    opt_prefix = '--'
    opts = {
        'verbose': {'is_flag': True, 'default': False, 'internal': True, 'display': True, 'help': 'Record all SSL/TLS info, not only critical info'},  # noqa: E501
        'parallel': {'is_flag': True, 'default': False, 'help': 'Test multiple hosts in parallel'},
        'warnings': {'type': str, 'default': None, 'help': 'Set to "batch" to stop on errors, and "off" to skip errors and continue'},  # noqa: E501
        'ids_friendly': {'is_flag': True, 'default': False, 'help': 'Avoid IDS blocking by skipping a few vulnerability checks'},  # noqa: E501
        'hints': {'is_flag': True, 'default': False, 'help': 'Additional hints to findings'},
        'server_defaults': {'is_flag': True, 'default': False, 'help': 'Displays the server default picks and certificate info'},  # noqa: E501
    }
    meta_opts = {
        PROXY: OPTS[PROXY],
        USER_AGENT: OPTS[USER_AGENT],
        HEADER: OPTS[HEADER],
        TIMEOUT: OPTS[TIMEOUT],
    }
    opt_key_map = {
        PROXY: 'proxy',
        USER_AGENT: 'user-agent',
        HEADER: 'reqheader',
        TIMEOUT: 'connect-timeout',
        'ipv6': '-6',
    }
    output_types = [Certificate, Vulnerability, Ip, Tag]
    proxy_http = True
    proxychains = False
    proxy_socks5 = False
    profile = 'io'
    install_pre = {
        'apk': ['hexdump', 'coreutils', 'procps'],
        'pacman': ['util-linux'],
        '*': ['bsdmainutils']
    }
    install_version = 'v3.2.0'
    install_cmd = (
        f'git clone --depth 1 --single-branch -b [install_version] https://github.com/drwetter/testssl.sh.git {CONFIG.dirs.share}/testssl.sh_[install_version] || true && '  # noqa: E501
        f'ln -sf {CONFIG.dirs.share}/testssl.sh_[install_version]/testssl.sh {CONFIG.dirs.bin}'
    )

    @staticmethod
    def on_cmd(self):
        output_path = self.get_opt_value(OUTPUT_PATH)
        if not output_path:
            output_path = f'{self.reports_folder}/.outputs/{self.unique_name}.json'
        self.output_path = output_path
        self.cmd += f' --jsonfile {self.output_path}'

        # Hack because target needs to be the last argument in testssl.sh
        if len(self.inputs) == 1:
            target = self.inputs[0]
            self.cmd = self.cmd.replace(f' {target}', '')
            self.cmd += f' {target}'

    @staticmethod
    def on_cmd_done(self):
        if not os.path.exists(self.output_path):
            yield Error(message=f'Could not find JSON results in {self.output_path}')
            return
        yield Info(message=f'JSON results saved to {self.output_path}')

        verbose = self.get_opt_value('verbose')
        with open(self.output_path, 'r') as f:
            data = json.load(f)
            bad_cyphers = {}
            retrieved_certificates = {}
            ignored_item_ids = ["scanTime", "overall_grade", "DNS_CAArecord"]
            ip_addresses = []
            host_to_ips = {}

            for item in data:
                host, ip = tuple(item['ip'].split('/'))
                id = item['id']
                # port = item['port']
                finding = item['finding']
                severity = item['severity'].lower()
                cwe = item.get('cwe')
                vuln_tags = ['ssl', 'tls']
                if cwe:
                    vuln_tags.append(cwe)

                # Skip ignored items
                if id.startswith(tuple(ignored_item_ids)):
                    continue

                # Add IP to address pool
                host_to_ips.setdefault(host, []).append(ip)
                if ip not in ip_addresses:
                    ip_addresses.append(ip)
                    yield Ip(
                        host=host,
                        ip=ip,
                        alive=True
                    )

                # Process errors
                if id.startswith("scanProblem"):
                    yield Error(message=finding)

                # Process bad ciphers
                elif id.startswith('cipher-'):
                    splited_item = item["finding"].split(" ")
                    concerned_protocol = splited_item[0]
                    bad_cypher = splited_item[-1]
                    bad_cyphers.setdefault(ip, {}).setdefault(concerned_protocol, []).append(bad_cypher)  # noqa: E501

                # Process certificates
                elif id.startswith('cert_') or id.startswith('cert '):
                    retrieved_certificates.setdefault(ip, []).append(item)

                # Process intermediate certificates
                elif id.startswith('intermediate_cert_'):
                    # TODO: implement this
                    pass

                # If info or ok, create a tag only if 'verbose' option is set
                elif severity in ['info', 'ok']:
                    if not verbose:
                        continue
                    yield Tag(
                        name=f'SSL/TLS [{id}]',
                        match=host,
                        extra_data={
                            'type': id,
                            'finding': finding,
                        }
                    )

                # Create vulnerability
                else:
                    if id in ['TLS1', 'TLS1_1']:
                        human_name = f'SSL/TLS deprecated protocol offered: {id}'
                    else:
                        human_name = f'SSL/TLS {id}: {finding}'
                    yield Vulnerability(
                        name=human_name,
                        matched_at=host,
                        ip=ip,
                        tags=vuln_tags,
                        severity=severity,
                        confidence='high',
                        extra_data={
                            'id': id,
                            'finding': finding
                        }
                    )

            # Creating vulnerability for the deprecated ciphers
            for ip, protocols in bad_cyphers.items():
                for protocol, cyphers in protocols.items():
                    yield Vulnerability(
                        name=f'SSL/TLS vulnerability ciphers for {protocol} deprecated',
                        matched_at=ip,
                        ip=ip,
                        confidence='high',
                        severity='low',
                        extra_data={
                            'cyphers': cyphers
                        }
                    )

            # Creating certificates for each founded target
            host_to_ips = {k: set(v) for k, v in host_to_ips.items()}
            for ip, certs in retrieved_certificates.items():
                host = [k for k, v in host_to_ips.items() if ip in v][0]
                cert_data = {
                    'host': host,
                    'ip': ip,
                    'fingerprint_sha256': None,
                    'subject_cn': None,
                    'subject_an': None,
                    'not_before': None,
                    'not_after': None,
                    'issuer_cn': None,
                    'self_signed': None,
                    'trusted': None,
                    'status': None,
                    'keysize': None,
                    'serial_number': None,
                }
                for cert in certs:
                    host = [k for k, v in host_to_ips.items() if ip in v][0]
                    id = cert['id']
                    finding = cert['finding']

                    if id.startswith('cert_crlDistributionPoints') and finding != '--':
                        # TODO not implemented, need to find a certificate that is revoked by CRL
                        cert_data['status'] = CERTIFICATE_STATUS_UNKNOWN

                    if id.startswith('cert_ocspRevoked'):
                        if finding.startswith('not revoked'):
                            cert_data['status'] = CERTIFICATE_STATUS_TRUSTED
                        else:
                            cert_data['status'] = CERTIFICATE_STATUS_REVOKED

                    if id.startswith('cert_fingerprintSHA256'):
                        cert_data['fingerprint_sha256'] = finding

                    if id.startswith('cert_commonName'):
                        cert_data['subject_cn'] = finding

                    if id.startswith('cert_subjectAltName'):
                        cert_data['subject_an'] = finding.split(" ")

                    if id.startswith('cert_notBefore'):
                        cert_data['not_before'] = datetime.strptime(finding, "%Y-%m-%d %H:%M")

                    if id.startswith('cert_notAfter'):
                        cert_data['not_after'] = datetime.strptime(finding, "%Y-%m-%d %H:%M")

                    if id.startswith('cert_caIssuers'):
                        cert_data['issuer_cn'] = finding

                    if id.startswith('cert_chain_of_trust'):
                        cert_data['self_signed'] = 'self signed' in finding

                    if id.startswith('cert_chain_of_trust'):
                        cert_data['trusted'] = finding.startswith('passed')

                    if id.startswith('cert_keySize'):
                        cert_data['keysize'] = int(finding.split(" ")[1])

                    if id.startswith('cert_serialNumber'):
                        cert_data['serial_number'] = finding

                    if id.startswith('cert ') and finding.startswith('-----BEGIN CERTIFICATE-----'):
                        cert_data['raw_value'] = finding

                # For the following attributes commented, it's because at the time of writting it
                # I did not found the value inside the result of testssl
                cert = Certificate(
                    **cert_data
                    # issuer_dn='',
                    # issuer='',
                    # TODO: delete the ciphers attribute from certificate outputType
                    # ciphers=None,
                    # TODO: need to find a way to retrieve the parent certificate,
                    # parent_certificate=None,
                )
                yield cert
                if cert.is_expired():
                    yield Vulnerability(
                        name='SSL certificate expired',
                        provider='testssl',
                        description='The SSL certificate is expired. This can easily lead to domain takeovers',
                        matched_at=host,
                        ip=ip,
                        tags=['ssl', 'tls'],
                        severity='medium',
                        confidence='high',
                        extra_data={
                            'id': id,
                            'expiration_date': Certificate.format_date(cert.not_after)
                        }
                    )
