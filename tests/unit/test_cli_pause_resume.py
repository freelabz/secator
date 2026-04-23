from click.testing import CliRunner
from secator.cli import cli


def test_pause_command_exists():
	runner = CliRunner()
	result = runner.invoke(cli, ['pause', '--help'])
	assert result.exit_code == 0


def test_resume_command_exists():
	runner = CliRunner()
	result = runner.invoke(cli, ['resume', '--help'])
	assert result.exit_code == 0
