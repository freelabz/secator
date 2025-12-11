import ifaddr
import ipaddress

from secator.decorators import task
from secator.output_types import Tag, Ip
from secator.runners import PythonRunner


@task()
class netdetect(PythonRunner):
    """Detect local network CIDR ranges."""
    output_types = [Tag, Ip]
    tags = ['network', 'recon']
    default_inputs = ''
    input_flag = None

    def yielder(self):
        adapters = ifaddr.get_adapters()
        for adapter in adapters:
            if adapter.name == 'lo' or adapter.name.lower().startswith('loopback'):
                continue
            yield Tag(
                name='net_interface',
                match='localhost',
                value=adapter.nice_name,
                category='info',
            )
            for ip in adapter.ips:
                if ip.is_IPv4:
                    try:
                        network = ipaddress.IPv4Network(f"{ip.ip}/{ip.network_prefix}", strict=False)
                        yield Ip(
                            ip=ip.ip,
                            host='localhost',
                            alive=True,
                        )
                        yield Tag(
                            name='net_cidr',
                            match='localhost',
                            value=str(network),
                            category='info',
                        )
                    except ValueError:
                        continue
