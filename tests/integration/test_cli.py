import os
import unittest
import subprocess
import warnings

from secator.runners import Command
from secator.output_types import Target, Port, Url, Info
from secator.serializers import JSONSerializer
from secator.rich import console

class TestCli(unittest.TestCase):

    def test_cli_pipe(self):
        os.environ['SECATOR_RUNNERS_FORCE_TTY'] = '1'
        pipe = 'secator x nmap -p 80 testphp.vulnweb.com | secator x httpx -json'
        cmd = Command.execute(pipe, name='secator_pipe', quiet=True, cls_attributes={'shell': True})
        console.print("Command secator_pipe finished with return code", cmd.return_code)
        console.print(cmd.toDict())
        port = '{"url": "http://testphp.vulnweb.com",'
        assert cmd.return_code == 0
        assert cmd.status == 'SUCCESS'
        assert port in cmd.output
        assert "Task httpx finished with status SUCCESS" in cmd.output
        assert "Task nmap finished with status SUCCESS" in cmd.output
