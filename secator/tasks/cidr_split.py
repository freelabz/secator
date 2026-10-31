import ipaddress

from secator.decorators import task
from secator.definitions import CIDR_RANGE
from secator.output_types import Tag
from secator.runners import PythonRunner


@task()
class cidr_split(PythonRunner):
    """CIDR splitter."""

    input_types = [CIDR_RANGE]
    output_types = [Tag]

    opts = {
        'subnet_size': {'type': int, 'default': 24, 'help': 'Split subnet size'}
    }

    def yielder(self):
        subnet_size = self.get_opt_value('subnet_size')
        for cidr in self.inputs:
            # Accept both IPv4 and IPv6 CIDRs.
            network = ipaddress.ip_network(cidr, strict=False)
            # If the network is already more specific than (or equal to) the
            # requested split prefix, keep it as-is: subnets(new_prefix=...)
            # raises ValueError when new_prefix < the network prefix.
            if network.prefixlen >= subnet_size:
                subnets = [network]
            else:
                subnets = network.subnets(new_prefix=subnet_size)
            for subnet in subnets:
                yield Tag(
                    category='info',
                    name='cidr_range',
                    value=str(subnet),
                    match=str(subnet),
                    extra_data={'parent': cidr},
                )
