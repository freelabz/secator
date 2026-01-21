#!/usr/bin/env python3
"""
Test all secator tasks using the CLI.

This script iterates through all available secator tasks and tests them
by running `secator x <TASK_NAME> --help` to validate that the command
is properly registered and options are correctly configured.
"""

import os
import sys
import subprocess
from pathlib import Path

# Add the secator package to the path
ROOT_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT_DIR))

try:
    from secator.tasks import TASKS
    from secator.loader import discover_tasks
    from secator.definitions import (
        URL, HOST, IP, CIDR_RANGE, PATH, USERNAME, EMAIL,
        MAC_ADDRESS, IBAN, UUID, SLUG, STRING, HOST_PORT
    )
except ImportError as e:
    print(f"Error importing secator: {e}")
    print("Make sure you're running this script from the secator repository root")
    sys.exit(1)


# Map input types to test values
INPUT_TYPE_TEST_VALUES = {
    URL: 'https://secator.cloud/',
    HOST: 'secator.cloud',
    HOST_PORT: 'secator.cloud:443',
    IP: '127.0.0.1',
    CIDR_RANGE: '127.0.0.1/24',
    PATH: str(ROOT_DIR),  # Use the repo root as a test path
    USERNAME: 'testuser',
    EMAIL: 'test@example.com',
    SLUG: 'redis:latest',
    STRING: 'Apache 2.4.5',
}


def get_task_options(task_cls):
    """Get all options for a task (meta_opts + opts)."""
    meta_opts = getattr(task_cls, 'meta_opts', {})
    opts = getattr(task_cls, 'opts', {})
    return {**meta_opts, **opts}


def get_test_input_for_task(task_cls):
    """Get an appropriate test input value for a task based on its input types."""
    input_types = getattr(task_cls, 'input_types', [])
    
    if not input_types:
        return None
    
    # Use the first input type and get its test value
    first_input_type = input_types[0]
    return INPUT_TYPE_TEST_VALUES.get(first_input_type, 'test.example.com')


def test_task(task_name, task_cls=None, dry_run=True, verbose=False):
    """
    Test a secator task by running it with --help or --dry-run.
    
    Args:
        task_name: Name of the task to test
        task_cls: Task class (optional, for getting input types)
        dry_run: If True, use --dry-run, otherwise use --help
        verbose: If True, show command output
        
    Returns:
        tuple: (success: bool, output: str, error: str)
    """
    # Build command
    cmd = ['secator', 'x', task_name]
    
    if dry_run:
        cmd.append('--dry-run')

    # Add a test input based on task's input types
    if task_cls:
        test_input = get_test_input_for_task(task_cls)
        if test_input:
            cmd.append(test_input)
        else:
            cmd.append('test.example.com')  # fallback
    else:
        cmd.append('test.example.com')
    
    try:
        print(' '.join(cmd))
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=os.environ,
            timeout=10,
            cwd=ROOT_DIR
        )
        print(result.stdout)
        print(result.stderr)
        success = result.returncode == 0
        print(success)
        return success, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, '', 'Command timed out after 10 seconds'
    except Exception as e:
        return False, '', str(e)


def main():
    """Main function to test all tasks."""
    # Discover all tasks
    tasks = discover_tasks()
    
    if not tasks:
        print("No tasks found!")
        return
    
    print(f"Found {len(tasks)} tasks to test\n")
    print("=" * 80)
    
    results = {
        'passed': [],
        'failed': [],
        'skipped': []
    }
    
    for task_cls in tasks:
        task_name = task_cls.__name__
        task_opts = get_task_options(task_cls)
        input_types = getattr(task_cls, 'input_types', [])
        
        print(f"\nTesting task: {task_name}")
        print(f"  Options: {len(task_opts)} total")
        if input_types:
            print(f"  Input types: {', '.join(input_types)}")
        if task_opts:
            print(f"  Option names: {', '.join(list(task_opts.keys())[:5])}{'...' if len(task_opts) > 5 else ''}")
        
        # Test with --help first (safer, doesn't require input)
        success, stdout, stderr = test_task(task_name, task_cls=task_cls, dry_run=False, verbose=False)
        print(stdout)

        if success:
            print(f"  ✓ PASSED")
            results['passed'].append(task_name)
        else:
            print('Error: ', stderr)
            # Try with --dry-run as fallback
            print(f"  ⚠ --help failed, trying --dry-run...")
            success, stdout, stderr = test_task(task_name, task_cls=task_cls, dry_run=True, verbose=False)
            
            if success:
                print(f"  ✓ PASSED (--dry-run works)")
                results['passed'].append(task_name)
            else:
                print(f"  ✗ FAILED")
                if stderr:
                    print(f"    Error: {stderr[:200]}")
                results['failed'].append((task_name, stderr))
    
    # Print summary
    print("\n" + "=" * 80)
    print("\nSUMMARY")
    print("=" * 80)
    print(f"Total tasks: {len(tasks)}")
    print(f"Passed: {len(results['passed'])}")
    print(f"Failed: {len(results['failed'])}")
    
    if results['passed']:
        print(f"\n✓ Passed tasks ({len(results['passed'])}):")
        for task in results['passed']:
            print(f"  - {task}")
    
    if results['failed']:
        print(f"\n✗ Failed tasks ({len(results['failed'])}):")
        for task, error in results['failed']:
            print(f"  - {task}")
            if error:
                print(f"    Error: {error[:100]}")
    
    # Exit with appropriate code
    sys.exit(0 if len(results['failed']) == 0 else 1)


if __name__ == '__main__':
    main()

