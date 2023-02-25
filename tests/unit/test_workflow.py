from celery import chain, chord
from secsy.celery import run_command, forward_results
from secsy.tools.http import httpx


def build_simple_chain_workflow():
	targets = ['bing.com', 'google.com', 'wikipedia.org', 'ibm.com', 'cnn.com', 'karate.com']
	task = chain(
	    httpx.si([], targets[0]),
	    httpx.s(targets[1]),
	    httpx.s(targets[2]),
	    httpx.s(targets[3]),
	    httpx.s(targets[4]),
	    httpx.s(targets[5]),
	)
	workflow = task.delay()
	results = workflow.get()
	urls = [r['url'] for r in results]
	print(urls)
	return workflow


def build_complex_workflow():
	targets = ['bing.com', 'google.com', 'wikipedia.org', 'ibm.com', 'cnn.com', 'karate.com']
	task = chain(
		forward_results.s([]),
	    httpx().s(targets[0]),
	    chord((
	        httpx().s(targets[1]),
	        httpx().s(targets[2]),
	    ), forward_results.s()),
	    httpx().s(targets[3]),
	    chord((
	        httpx().s(targets[4]),
	        httpx().s(targets[5]),
	    ), forward_results.s())
	)
	workflow = task.delay()
	results = workflow.get()
	urls = [r['url'] for r in results]
	print(urls)
	return workflow


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
# 	# print([r for r in results if r['_type'] == 'url'])