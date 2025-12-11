import click

from secator.decorators import task
from secator.output_types import Tag
from secator.runners import PythonRunner
from secator.rich import console


@task()
class prompt(PythonRunner):
    """Prompt the user for a CIDR range."""
    output_types = [Tag]
    tags = ['network', 'recon']
    default_inputs = ''
    input_flag = None
    opts = {
        'yes': {
            'is_flag': True,
            'default': False,
            'short': 'y',
            'help': 'Auto-accept the prompt and forward all objects',
        },
        'message': {
            'type': str,
            'default': 'Validate {input}?',
            'help': 'The message to display to the user',
        },
    }

    def yielder(self):
        yes = self.run_opts['yes']
        if len(self.inputs) == 0:
            return
        if yes:
            console.print('\n\[[bold green]PROMPT[/]] [bold green]Auto-accepted all inputs.[/]')
        else:
            console.print('\n\[[bold red]PROMPT[/]] [bold red]Prompting user for validation...[/]')
        for input in self.inputs:
            if yes or click.confirm(self.run_opts['message'].format(input=input), default=True):
                yield Tag(
                    name='user_input',
                    match='auto' if yes else 'prompt',
                    value=input,
                    category='info',
                )
