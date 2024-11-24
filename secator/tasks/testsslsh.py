import json
import os
from datetime import datetime

from secator.decorators import task
from secator.output_types import Vulnerability, Certificate, Error, Info
from secator.definitions import (PROXY, DELAY, RATE_LIMIT, RETRIES,
                                TIMEOUT, THREADS, OPT_NOT_SUPPORTED,
                                USER_AGENT, HEADER, OUTPUT_PATH, CERTIFICATE_STATUS_UNKNOWN,
                                CERTIFICATE_STATUS_TRUSTED, CERTIFICATE_STATUS_REVOKED)
from secator.tasks._categories import VulnMulti


@task()
class testsslsh(VulnMulti):
    output_types = [Certificate, Vulnerability]
    install_cmd = (
        'sudo git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh && ',
        'sudo ln -s /opt/testssl.sh/testssl.sh /usr/bin'
    )
    cmd = 'testssl.sh'
    # TODO add more of the default options
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
        with open(self.output_path, 'r') as f:
            data = json.load(f)
            bad_cyphers_by_protocols = {}
            retrieved_certificates = {}
            list_of_ignored_findings_id = ["scanTime", "overall_grade", "DNS_CAArecord"]
            targets_in_result = []
            for finding in data:
                if not (finding["ip"] in targets_in_result):
                    targets_in_result.append(finding["ip"])
                if (finding['severity'] != 'INFO') and (finding['severity'] != 'OK'):
                    if finding["id"] in list_of_ignored_findings_id:
                        continue
                    elif (finding["id"] == "TLS1") or finding["id"] == "TLS1_1":
                        matched_at, ip = finding["ip"].split("/")
                        yield Vulnerability(
                            matched_at=matched_at,
                            name=f'SSL/TLS deprecated protocol {finding["id"]} supported',
                            severity=finding["severity"],
                        )
                        pass
                    elif finding["id"].startswith('cipherlist_OBSOLETED'):
                        bad_cyphers_by_protocols.setdefault(finding["ip"], {})["severity"] = finding["severity"]
                    elif finding["id"].startswith('cipher-'):
                        splited_finding = finding["finding"].split(" ")
                        concerned_protocol = splited_finding[0]
                        bad_cypher = splited_finding[-1]
                        bad_cyphers_by_protocols.setdefault(finding["ip"], {}) \
                                                .setdefault(concerned_protocol, []) \
                                                .append(bad_cypher)
                    else:
                        matched_at, ip = finding["ip"].split("/")
                        yield Vulnerability(
                            matched_at=matched_at,
                            name=f'SSL/TLS vulnerability {finding["id"]}',
                            severity=finding["severity"],
                        )
                if finding["id"].startswith('cert_'):
                    retrieved_certificates.setdefault(finding["ip"], {})[finding["id"]] = finding["finding"]
            # Creating vulnerability for the deprecated ciphers
            for target in bad_cyphers_by_protocols:
                matched_at, ip = target.split("/")
                for protocol in bad_cyphers_by_protocols[target]:
                    if isinstance(bad_cyphers_by_protocols[target][protocol], list):
                        cipher_list_string = ";".join(bad_cyphers_by_protocols[target][protocol])
                        yield Vulnerability(
                                matched_at=matched_at,
                                name=f'SSL/TLS vulnerability ciphers for {protocol} deprecated : {cipher_list_string}',
                                severity=bad_cyphers_by_protocols[target]["severity"],
                            )
            # Creating certificates for each founded target
            for target in targets_in_result:
                host, ip = target.split("/")
                certificate_to_use = retrieved_certificates[target]
                # OCSP is checked last because it have precedence over CRL
                if certificate_to_use['cert_crlDistributionPoints'] != '--':
                    #TODO not implemented, need to find a certificate that is revoked by CRL
                    status = CERTIFICATE_STATUS_UNKNOWN
                if 'cert_ocspRevoked' in certificate_to_use:
                    if certificate_to_use['cert_ocspRevoked'].startswith('not revoked'):
                        status = CERTIFICATE_STATUS_TRUSTED
                    else:
                        status = CERTIFICATE_STATUS_REVOKED
                # For the following attributes commented, it's because at the time of writting it
                # I did not found the value inside the result of testssl
                yield Certificate(
                    host=host,
                    ip=ip,
                    fingerprint_sha256=certificate_to_use['cert_fingerprintSHA256'],
                    subject_cn=certificate_to_use['cert_commonName'],
                    subject_an=certificate_to_use['cert_subjectAltName'].split(" "),
                    not_before=datetime.strptime(certificate_to_use['cert_notBefore'], "%Y-%m-%d %H:%M"),
                    not_after=datetime.strptime(certificate_to_use['cert_notAfter'], "%Y-%m-%d %H:%M"),
                    # issuer_dn='',
                    issuer_cn=certificate_to_use['cert_caIssuers'],
                    # issuer='',
                    self_signed='self signed' in certificate_to_use['cert_chain_of_trust'],
                    trusted=certificate_to_use['cert_chain_of_trust'].startswith('passed'),
                    status=status,
                    # During testing keysize was always of the form "ALG SIZE bits ..."
                    keysize=int(certificate_to_use['cert_keySize'].split(" ")[1]),
                    serial_number=certificate_to_use['cert_serialNumber'],
                    # TODO: delete the ciphers attribute from certificate outputType
                    # ciphers=None,
                    # TODO: need to find a way to retrieve the parent certificate,
                    # parent_certificate=None,
                )
