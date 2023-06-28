from celery import chain
from secator.celery import app
from secator.tasks import httpx
import unittest
import json
from secator.definitions import DEBUG
from secator.utils_test import mock_command, FIXTURES_TASKS, TEST_TASKS
from secator.celery import forward_results
from secator.rich import console

TARGETS = ['bing.com', 'google.com', 'wikipedia.org', 'ibm.com', 'cnn.com', 'karate.com']


class TestAdHocWorkflow(unittest.TestCase):

	def test_chain(self):
		if not httpx in TEST_TASKS:
			return

		with mock_command(httpx, fixture=[FIXTURES_TASKS[httpx]] * len(TARGETS)):
			sigs = [forward_results.si([])] + [httpx.s(target) for target in TARGETS]
			workflow = chain(*sigs)
			result = workflow.apply()
			results = result.get()
			if DEBUG > 1:
				console.print_json(json.dumps(results))
			urls = [r.url for r in results]
			self.assertEqual(len(urls), len(TARGETS))

	# def test_chain_with_results(self):
	# 	existing_results = [{
	# 		"url": "https://example.synology.me",
	# 		"method": "GET",
	# 		"status_code": 200,
	# 		"words": 438,
	# 		"lines": 136,
	# 		"content_type":
	# 		"text/html",
	# 		"content_length": 11577,
	# 		"host": "82.66.157.114",
	# 		"time": 0.16246860100000002,
	# 		"_source": "httpx",
	# 		"_type": "url"
	# 	}]
	# 	with mock_command(httpx, fixture=[FIXTURES_TASKS[httpx]] * len(TARGETS)):
	# 		sigs = [httpx.s(target) for target in TARGETS]
	# 		sigs = [forward_results.si(existing_results)] + sigs
	# 		workflow = chain(*sigs)
	# 		result = workflow.apply()
	# 		results = result.get()
	# 		if DEBUG:
	# 			console.print_json(json.dumps(results))
	# 		urls = [r['url'] for r in results]
	# 		self.assertEqual(len(urls), len(TARGETS))
	# 		self.assertIn(existing_results[0], results)

	# def test_complex_workflow():
	# 	targets = ['bing.com', 'google.com', 'wikipedia.org', 'ibm.com', 'cnn.com', 'karate.com']
	# 	task = chain(
	# 		forward_results.s([]),
	# 		httpx().s(targets[0]),
	# 		chord((
	# 			httpx().s(targets[1]),
	# 			httpx().s(targets[2]),
	# 		), forward_results.s()),
	# 		httpx().s(targets[3]),
	# 		chord((
	# 			httpx().s(targets[4]),
	# 			httpx().s(targets[5]),
	# 		), forward_results.s())
	# 	)
	# 	workflow = task.delay()
	# 	results = workflow.get()
	# 	urls = [r['url'] for r in results]
	# 	print(urls)
	# 	return workflow


	# def test_nested_collect():
	# 	console.log(task)
	# 	workflow = task.delay()
	# 	results = workflow.get()
	# 	console.print_item(json.dumps(results))
	# 	# results = get_results(workflow)
	# 	# console.log(results)
	# 	# console.log([r['url'] for r in results])
	# 	# urls = [r['url'] for r in results]
	# 	# for target in targets:
	# 	#     assert any(target in url for url in urls)
	# 	return workflow

	# 	# Polling approach
	# 	# for task_id, name, result in poll_task(find_root_task(workflow), seen):
	# 	#     print(task_id, name, result)
	# 	#     results.append(result)
	# 	# print([r for r in results if r._type == 'url'])