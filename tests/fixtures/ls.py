from secator.runners import Command
from secator.decorators import task
from secator.output_types import Vulnerability


@task()
class ls(Command):
    cmd = 'ls -al'
    output_types = [Vulnerability]
    output_map = {
        Vulnerability: {}
	}

    @staticmethod
    def item_loader(self, line):
        fields = ['permissions', 'link_count', 'owner', 'group', 'size', 'month', 'day', 'hour', 'path']
        result = [c for c in line.split(' ') if c]
        if len(result) != len(fields):
            return None
        data = {}
        for ix, value in enumerate(result):
            data[fields[ix]] = value

        # Output vulnerabilities
        permissions = data['permissions']
        path = data['path']
        full_path = f'{self.inputs[0]}/{path}'
        if permissions[-2] == 'w':  # found a vulnerability !
            yield Vulnerability(
                name='World-writeable path',
                severity='high',
                confidence='high',
                provider='ls',
                matched_at=full_path,
                extra_data={k: v for k, v in data.items() if k != 'path'}
            )
