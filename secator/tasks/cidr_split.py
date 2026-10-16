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
            network = ipaddress.IPv4Network(cidr, strict=False)
            subnets = network.subnets(new_prefix=subnet_size)
            for subnet in subnets:
                yield Tag(
                    category='info',
                    name='cidr_range',
                    value=str(subnet),
                    match=str(subnet),
                    extra_data={'parent': cidr},
                )
