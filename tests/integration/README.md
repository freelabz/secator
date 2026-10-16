# Integration Tests

This directory contains integration tests for secator that test the full functionality with real tools and services.

## Test Files

- `test_tasks.py` - Tests for individual secator tasks
- `test_workflows.py` - Tests for secator workflows
- `test_scans.py` - Tests for secator scans
- `test_celery.py` - Tests for Celery task execution with local worker
- `test_worker.py` - Tests for worker functionality
- `test_remote_worker.py` - Tests for remote worker functionality using Docker containers

## Running Tests

### All Integration Tests

```bash
secator test integration
```

### Specific Test Files

```bash
# Run only remote worker tests
secator test integration --test test_remote_worker

# Run multiple test files
secator test integration --test test_celery,test_worker,test_remote_worker

# Run specific tasks
secator test integration --tasks httpx,nmap

# Run specific workflows
secator test integration --workflows host_recon,url_crawl
```

## Remote Worker Tests

The `test_remote_worker.py` file contains tests that verify secator works correctly with remote workers running in Docker containers. These tests:

1. Spin up a Docker Compose stack with:
   - Redis (as Celery broker and result backend)
   - Secator worker container

2. Run tasks remotely and verify results are correctly returned

3. Test various Celery patterns (chains, chords) with remote execution

### Prerequisites

To run remote worker tests, you need:

- Docker installed and running
- Docker Compose v2.x or higher
- Redis addon installed: `secator install addons redis`

### Test Environment

The remote worker tests create a temporary Docker Compose configuration that:
- Uses the latest `freelabz/secator` Docker image
- Exposes Redis on port 6379 for the test runner to connect
- Runs the worker in command-runner mode for better debugging

### Manual Testing

You can also manually test remote workers using the docker-compose.yml in the project root:

```bash
# Start the stack
docker compose up -d

# Run a task remotely
docker compose exec secator secator x httpx testphp.vulnweb.com

# Stop the stack
docker compose down
```

## Test Lab Services

Some integration tests require additional services (Juice Shop, WordPress, etc.). These are managed by:

- `setup.sh` - Starts test lab services
- `teardown.sh` - Stops test lab services  
- `docker-compose.yml` - Defines test lab services

The test lab is automatically set up when running `test_celery.py` and similar tests.

## Environment Variables

The following environment variables are used during testing:

- `TEST_TASKS` - Comma-separated list of tasks to test
- `TEST_WORKFLOWS` - Comma-separated list of workflows to test
- `TEST_SCANS` - Comma-separated list of scans to test
- `TEST_NO_CLEANUP` - Set to '1' to skip cleanup (useful for debugging)
- `SECATOR_CELERY_BROKER_URL` - Celery broker URL (set by remote worker tests)
- `SECATOR_CELERY_RESULT_BACKEND` - Celery result backend URL (set by remote worker tests)

## Debugging

To keep test lab running between test runs (for faster iteration):

```bash
secator test integration --no-cleanup --test test_remote_worker
```

This will keep the Docker containers running so subsequent test runs don't need to wait for container startup.
