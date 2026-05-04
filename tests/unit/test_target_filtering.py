"""
Tests for fix of issue #1070: subsequent workflow tasks in scan not defaulting to original targets.

Design: Approach B — scope-tagged Target emission from mark_runner_started.
"""
import unittest
from unittest.mock import patch

from secator.decorators import task
from secator.definitions import HOST, HOST_PORT, URL
from secator.output_types import Port, Tag, Target, Technology, Url
from secator.runners import PythonRunner
from secator.template import TemplateLoader

# --- Mock tasks (record inputs for assertions) ---

MOCK_INPUTS = {}


@task()
class w1_1(PythonRunner):
    """HOST → Port (ports 80, 443, 445)."""
    input_types = [HOST]
    output_types = [Port]

    def yielder(self):
        MOCK_INPUTS['w1_1'] = sorted(self.inputs)
        for target in self.inputs:
            yield Port(ip=target, port=80, protocol='tcp')
            yield Port(ip=target, port=443, protocol='tcp')
            yield Port(ip=target, port=445, protocol='tcp')


@task()
class w1_2(PythonRunner):
    """URL → Technology."""
    input_types = [URL]
    output_types = [Technology]

    def yielder(self):
        MOCK_INPUTS['w1_2'] = sorted(self.inputs)
        for target in self.inputs:
            yield Technology(match=target, product='Apache', version='2.4')


@task()
class w2_1(PythonRunner):
    """HOST_PORT containing '445' → Tag(category='secret')."""
    input_types = [HOST_PORT]
    output_types = [Tag]

    def yielder(self):
        MOCK_INPUTS['w2_1'] = sorted(self.inputs)
        for target in self.inputs:
            yield Tag(name='smb', match=target, category='secret')


@task()
class w2_2(PythonRunner):
    """All HOST_PORT targets → Url(status_code=200)."""
    input_types = [HOST_PORT]
    output_types = [Url]

    def yielder(self):
        MOCK_INPUTS['w2_2'] = sorted(self.inputs)
        for target in self.inputs:
            yield Url(url=f'http://{target}', status_code=200)


@task()
class w2_3(PythonRunner):
    """Tag(secret) + Url(200) → Tag(verified)."""
    input_types = [HOST_PORT, URL]
    output_types = [Tag]

    def yielder(self):
        MOCK_INPUTS['w2_3'] = sorted(self.inputs)
        for target in self.inputs:
            yield Tag(name='found-secret', match=target, category='verified')


MOCK_TASK_CLASSES = [w1_1, w1_2, w2_1, w2_2, w2_3]


# --- In-memory configs ---

def make_workflow1_config():
    return TemplateLoader(input={
        'name': 'workflow1',
        'type': 'workflow',
        'input_types': ['url', 'host'],
        'tasks': {
            'w1_1': {
                'targets_': [
                    {'type': 'target', 'field': 'name', 'condition': "target.type == 'host'"}
                ]
            },
            'w1_2': {
                'targets_': [
                    {'type': 'target', 'field': 'name', 'condition': "target.type == 'url'"}
                ]
            },
        }
    })


def make_workflow2_config():
    return TemplateLoader(input={
        'name': 'workflow2',
        'type': 'workflow',
        'input_types': ['host:port'],
        'tasks': {
            'w2_1': {
                'targets_': [
                    {'type': 'target', 'field': 'name', 'condition': "'445' in target.name"}
                ]
            },
            'w2_2': {},
            'w2_3': {
                'targets_': [
                    {'type': 'tag', 'field': 'match', 'condition': "tag.category == 'secret'"},
                    {'type': 'url', 'field': 'url', 'condition': 'url.status_code == 200'},
                ]
            },
        }
    })


def make_scan_config():
    return TemplateLoader(input={
        'name': 'test_scan',
        'type': 'scan',
        'input_types': ['url', 'host'],
        'workflows': {
            'workflow1': {},
            'workflow2': {
                'targets_': [
                    {'type': 'port', 'field': '{host}:{port}'}
                ]
            },
        }
    })


def patched_discover_tasks():
    """Return only mock task classes (avoids slow real task discovery in unit tests)."""
    return MOCK_TASK_CLASSES


def patched_find_templates():
    """Return in-memory workflow/scan configs."""
    return [make_workflow1_config(), make_workflow2_config(), make_scan_config()]
