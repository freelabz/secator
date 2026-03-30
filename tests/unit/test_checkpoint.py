import json
import pytest
from pathlib import Path
from secator.runners.checkpoint import Checkpoint


def test_checkpoint_roundtrip(tmp_path):
    cp = Checkpoint(
        runner_type='task',
        runner_id='abc-123',
        runner_name='nmap',
        targets=['10.0.0.1', '10.0.0.2'],
        opts={'ports': '80,443'},
        context={'workspace_name': 'default'},
        completed_inputs=['10.0.0.1'],
        pause_method='signal',
        process_pid=12345,
    )
    cp.save(tmp_path)
    loaded = Checkpoint.load(tmp_path)
    assert loaded.runner_id == 'abc-123'
    assert loaded.completed_inputs == ['10.0.0.1']
    assert loaded.pause_method == 'signal'


def test_checkpoint_load_missing(tmp_path):
    assert Checkpoint.load(tmp_path) is None


def test_checkpoint_remaining_inputs():
    cp = Checkpoint(
        runner_type='task',
        runner_id='abc-123',
        runner_name='nmap',
        targets=['10.0.0.1', '10.0.0.2', '10.0.0.3'],
        opts={},
        context={},
        completed_inputs=['10.0.0.1', '10.0.0.2'],
    )
    assert cp.remaining_inputs == ['10.0.0.3']


def test_checkpoint_remaining_inputs_empty_completed():
    cp = Checkpoint(
        runner_type='task',
        runner_id='abc-123',
        runner_name='nmap',
        targets=['10.0.0.1', '10.0.0.2'],
        opts={},
        context={},
        completed_inputs=[],
    )
    # When no completed inputs, all targets remain (restart from scratch)
    assert cp.remaining_inputs == ['10.0.0.1', '10.0.0.2']
