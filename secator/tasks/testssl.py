import json
import os
from datetime import datetime

from secator.config import CONFIG
from secator.decorators import task
from secator.output_types import Vulnerability, Certificate, Error, Info, Ip, Tag
from secator.definitions import (PROXY, DELAY, RATE_LIMIT, RETRIES,
                                TIMEOUT, THREADS, OPT_NOT_SUPPORTED,
                                USER_AGENT, HEADER, OUTPUT_PATH, CERTIFICATE_STATUS_UNKNOWN,
                                CERTIFICATE_STATUS_TRUSTED, CERTIFICATE_STATUS_REVOKED)
from secator.tasks._categories import VulnMulti


@task()
class testssl(VulnMulti):
    output_types = [Certificate, Vulnerability, Ip, Tag]
    install_cmd = (
        f'git clone --depth 1 https://github.com/drwetter/testssl.sh.git {CONFIG.dirs.share}/testssl.sh || true && '
        f'ln -sf {CONFIG.dirs.share}/testssl.sh/testssl.sh {CONFIG.dirs.bin}'
    )
    cmd = 'testssl.sh'
    # TODO add more of the default options
    opts = {
        'verbose': {'is_flag': True, 'default': False, 'internal': True, 'display': True, 'help': 'Record all SSL/TLS info, not only critical info'}  # noqa: E501
    }
    opt_key_map = {
        PROXY: 'proxy',
        USER_AGENT: 'user-agent',
        HEADER: OPT_NOT_SUPPORTED,  # TODO : available through 'reqheader' need testing before prod
        DELAY: OPT_NOT_SUPPORTED,
        RATE_LIMIT: OPT_NOT_SUPPORTED,
        RETRIES: OPT_NOT_SUPPORTED,
        TIMEOUT: OPT_NOT_SUPPORTED,
        THREADS: OPT_NOT_SUPPORTED,
    }
    opt_prefix = '--'
    input_flag = None
    file_flag = '-iL'
    #Supported proxy
    proxy_http = True
    proxychains = False  # Because I did not test could be True
    proxy_socks5 = False  # Because I did not test could be True
    profile = 'io'  # Todo confirm

    @staticmethod
    def on_init(self):
        output_path = self.get_opt_value(OUTPUT_PATH)
        if not output_path:
            output_path = f'{self.reports_folder}/.outputs/{self.unique_name}.json'
        self.output_path = output_path
        self.cmd += f' --jsonfile {self.output_path}'

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

                # Add IP to address pool
                host_to_ips.setdefault(host, []).append(ip)
                if ip not in ip_addresses:
                    ip_addresses.append(ip)
                    yield Ip(
                        host=host,
                        ip=ip,
                        alive=True
                    )

                # Skip ignored items or low severity items
                if id.startswith(tuple(ignored_item_ids)):
                    continue

                # Ignore low severity items if verbose is not set
                if severity in ['info', 'ok'] and not verbose:
                    continue

                # If info or ok, create a tag, not a vulnerability
                if severity in ['info', 'ok']:
                    yield Tag(
                        name=f'SSL/TLS [{id}]',
                        match=host,
                        extra_data={
                            'type': id,
                            'finding': finding,
                        }
                    )

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

                # Create vulnerability for deprecated protocols, obsolete ciphers and bad ciphers
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
                cert_data = {
                    'host': [k for k, v in host_to_ips.items() if ip in v][0],
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

                    # OCSP is checked last because it have precedence over CRL
                    if id.startswith('cert_crlDistributionPoints') and finding != '--':
                        #TODO not implemented, need to find a certificate that is revoked by CRL
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
                yield Certificate(
                    **cert_data
                    # issuer_dn='',
                    # issuer='',
                    # TODO: delete the ciphers attribute from certificate outputType
                    # ciphers=None,
                    # TODO: need to find a way to retrieve the parent certificate,
                    # parent_certificate=None,
                )
