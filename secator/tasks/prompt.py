import os
import signal
import click

from secator.decorators import task
from secator.output_types import Tag
from secator.runners import PythonRunner
from secator.rich import console
from secator.config import CONFIG


def _is_ci():
    """Check if running in CI environment."""
    return any(os.environ.get(var) for var in ('CI', 'CONTINUOUS_INTEGRATION', 'GITHUB_ACTIONS', 'GITLAB_CI', 'JENKINS_URL', 'BUILDKITE'))  # noqa: E501


def confirm_with_timeout(message, default=True, timeout=CONFIG.runners.prompt_timeout):
    """Prompt user with optional timeout.

    Args:
        message: The prompt message to display
        default: Default value if timeout occurs
        timeout: Timeout in seconds (0 to disable)

    Returns:
        User's response or default value on timeout
    """
    if timeout and timeout > 0:
        def timeout_handler(signum, frame):
            raise TimeoutError('Prompt timeout')

        old_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(timeout)
        try:
            result = click.confirm(message, default=default)
        except (TimeoutError, KeyboardInterrupt):
            console.print(f'\n\[[bold red]PROMPT[/]] [bold red]Prompt timed out after {timeout}s, continuing...[/]')
            result = default
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)
        return result
    else:
        return click.confirm(message, default=default)


@task()
class prompt(PythonRunner):
    """Prompt the user."""
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
        yes = self.run_opts.get('yes', False)
        in_ci = _is_ci()

        if len(self.inputs) == 0:
            return

        # Auto-accept in CI or if yes flag is set
        if yes or in_ci:
            console.print('\n\[[bold green]PROMPT[/]] [bold green]Auto-accepted all inputs.[/]')
        else:
            console.print('\n\[[bold red]PROMPT[/]] [bold red]Prompting user for validation ({timeout}s timeout)...[/]'.format(timeout=CONFIG.runners.prompt_timeout))  # noqa: E501

        for input in self.inputs:
            if yes or in_ci:
                result = True
            else:
                result = confirm_with_timeout(
                    self.run_opts['message'].format(input=input),
                    default=True,
                    timeout=CONFIG.runners.prompt_timeout
                )

            if result:
                yield Tag(
                    name='user_input',
                    match='auto' if (yes or in_ci) else 'prompt',
                    value=input,
                    category='info',
                )
