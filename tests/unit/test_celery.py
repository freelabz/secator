from secsy.celery import *
import unittest
from secsy.tasks import ffuf

class TestCeleryCommand(unittest.TestCase):

    def test_chunked_run_command(self):
        result = run_command.apply(
            args=[
                [],
                'ffuf',
                ['https://jahmyst.synology.me', 'https://media.jahmyst.synology.me']
            ]
        )
        results = result.get()
        self.assertTrue(isinstance(results, list))

    # def test_chunked_run_command_delay(self):
    #     result = run_command.delay(
    #         [],
    #         'ffuf',
    #         ['https://jahmyst.synology.me', 'https://media.jahmyst.synology.me'],
    #         opts={
    #             'sync': False
    #         }
    #     )
    #     results = result.get()
    #     self.assertTrue(isinstance(results, dict))
    #     self.assertTrue('results' in results)

    # def test_chunked_command_delay(self):
    #     result = ffuf.delay(
    #         ['https://jahmyst.synology.me', 'https://media.jahmyst.synology.me'],
    #         print_cmd=True,
    #         print_item=True,
    #     )
    #     ffuf.poll(result)
    #     results = result.get()
    #     print(results)
