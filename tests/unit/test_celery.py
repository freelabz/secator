# from secator.celery import *
# import unittest


# class TestCeleryCommand(unittest.TestCase):

#     def test_parent_run_command(self):
#         result = run_command.apply(
#             args=[
#                 [],
#                 'ffuf',
#                 ['https://mydomain.com', 'https://media.mydomain.com']
#             ]
#         )
#         results = result.get()
#         self.assertTrue(isinstance(results, list))

    # def test_parent_run_command_delay(self):
    #     result = run_command.delay(
    #         [],
    #         'ffuf',
    #         ['https://mydomain.com', 'https://media.mydomain.com'],
    #         opts={
    #             'sync': False
    #         }
    #     )
    #     results = result.get()
    #     self.assertTrue(isinstance(results, dict))
    #     self.assertTrue('results' in results)

    # def test_parent_command_delay(self):
    #     result = ffuf.delay(
    #         ['https://mydomain.com', 'https://media.mydomain.com'],
    #         print_cmd=True,
    #         print_item=True,
    #     )
    #     ffuf.poll(result)
    #     results = result.get()
    #     print(results)
