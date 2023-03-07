from secsy.celery import *
import unittest


# class TestCeleryCommand(unittest.TestCase):

#     def test_chunked_run_command(self):
#         result = run_command.apply(
#             args=[
#                 [],
#                 'ffuf',
#                 ['https://***REMOVED***', 'https://media.***REMOVED***']
#             ]
#         )
#         results = result.get()
#         self.assertTrue(isinstance(results, list))

    # def test_chunked_run_command_delay(self):
    #     result = run_command.delay(
    #         [],
    #         'ffuf',
    #         ['https://***REMOVED***', 'https://media.***REMOVED***'],
    #         opts={
    #             'sync': False
    #         }
    #     )
    #     results = result.get()
    #     self.assertTrue(isinstance(results, dict))
    #     self.assertTrue('results' in results)

    # def test_chunked_command_delay(self):
    #     result = ffuf.delay(
    #         ['https://***REMOVED***', 'https://media.***REMOVED***'],
    #         print_cmd=True,
    #         print_item=True,
    #     )
    #     ffuf.poll(result)
    #     results = result.get()
    #     print(results)
