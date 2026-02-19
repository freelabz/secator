# Async Hooks System Design

**Date:** 2026-02-19
**Status:** Approved
**Author:** Claude + jahmyst

## Problem Statement

The current hook system in Secator is synchronous - hooks block execution while running. For I/O-heavy hooks like MongoDB updates, this creates performance bottlenecks:

1. `update_finding` is called for every finding, blocking the runner
2. High-frequency MongoDB calls put pressure on the database
3. No batching mechanism exists for bulk operations

## Goals

- Enable async hook execution without blocking the runner
- Batch database operations to reduce MongoDB load
- Maintain backward compatibility with existing sync hooks
- Collect and report errors from async operations
- Ensure all pending operations complete before runner finishes

## Non-Goals

- Changing the behavior of existing sync hooks
- Making `update_runner` async (needs immediate context ID)
- Supporting async hooks outside of the Runner lifecycle

## Design

### Detection Mechanism

Hooks declare themselves as async using Python's native `async def` syntax:

```python
# Sync hook (unchanged)
def update_runner(self):
    ...

# Async hook (new)
async def update_finding(self, items: list):
    ...
```

The runner detects async hooks using `inspect.iscoroutinefunction()` and routes them to the `AsyncHookManager`.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         Runner                               │
│  ┌─────────────────┐    ┌─────────────────────────────────┐ │
│  │   run_hooks()   │───▶│       AsyncHookManager          │ │
│  │                 │    │  ┌───────────┐  ┌────────────┐  │ │
│  │ • detect async  │    │  │ BatchQueue│  │ ThreadPool │  │ │
│  │ • route to mgr  │    │  │ (per hook)│─▶│ (shared)   │  │ │
│  └─────────────────┘    │  └───────────┘  └────────────┘  │ │
│                         │  ┌───────────┐  ┌────────────┐  │ │
│                         │  │  Errors   │  │   Flush    │  │ │
│                         │  │ Collector │  │  Triggers  │  │ │
│                         └──┴───────────┴──┴────────────┴──┘ │
└─────────────────────────────────────────────────────────────┘
```

### Components

#### AsyncHookManager (`secator/runners/_async.py`)

Manages async hook execution with batching and thread pooling.

```python
class AsyncHookManager:
    def __init__(self, runner, pool_size=None, default_batch_size=100,
                 default_batch_interval=5.0):
        self.runner = runner
        self.pool = ThreadPoolExecutor(max_workers=pool_size)
        self.batch_queues = {}      # {hook_name: BatchQueue}
        self.errors = []            # Collected errors
        self.flush_timers = {}      # {hook_name: Timer}
        self.lock = threading.Lock()

    def submit(self, hook_fn, hook_name, *args):
        """Submit an item to a hook's batch queue."""

    def flush(self, hook_name):
        """Flush a specific hook's batch queue."""

    def flush_all(self):
        """Flush all queues and wait for completion."""

    def shutdown(self):
        """Shutdown the thread pool gracefully."""
```

#### BatchQueue (`secator/runners/_async.py`)

Thread-safe queue with deduplication support.

```python
class BatchQueue:
    def __init__(self, hook_fn, batch_size, batch_interval, batch_key='_uuid'):
        self.hook_fn = hook_fn
        self.batch_size = batch_size
        self.batch_interval = batch_interval
        self.batch_key = batch_key
        self.items = {}  # {key: (runner, item)} - dict for dedup
        self.lock = threading.Lock()

    def add(self, runner, item):
        """Add item, return True if batch_size reached."""
        with self.lock:
            key = getattr(item, self.batch_key, id(item))
            self.items[key] = (runner, item)  # Latest wins
            return len(self.items) >= self.batch_size

    def drain(self):
        """Remove and return all items."""
        with self.lock:
            items = list(self.items.values())
            self.items = {}
            return items
```

### Runner Integration

Changes to `secator/runners/_base.py`:

```python
class Runner:
    def __init__(self, ...):
        # Lazy initialization
        self._async_hook_manager = None

    @property
    def async_hook_manager(self):
        if self._async_hook_manager is None:
            self._async_hook_manager = AsyncHookManager(self)
        return self._async_hook_manager

    def run_hooks(self, hook_type, *args, sub='hooks'):
        for hook in self.resolved_hooks[hook_type]:
            if inspect.iscoroutinefunction(hook):
                self._submit_async_hook(hook, hook_type, *args, sub=sub)
                continue
            # ... existing sync hook execution ...

    def _finalize(self):
        # Flush async hooks and collect errors
        if self._async_hook_manager is not None:
            errors = self._async_hook_manager.flush_all()
            for error in errors:
                self.add_result(error, hooks=False)
            self._async_hook_manager.shutdown()
```

### MongoDB Hooks Migration

Changes to `secator/hooks/mongodb.py`:

```python
# Batch configuration
BATCH_CONFIG = {
    'update_finding': {
        'batch_size': CONFIG.addons.mongodb.batch_size,
        'batch_interval': CONFIG.addons.mongodb.batch_interval
    }
}

# AFTER: async with batch signature
async def update_finding(self, items: list):
    """Batch upsert findings to MongoDB."""
    if not items:
        return items

    client = get_mongodb_client()
    db = client.main

    operations = []
    for item in items:
        if type(item) not in OUTPUT_TYPES:
            continue
        update = item.toDict()
        _id = ObjectId(item._uuid) if ObjectId.is_valid(item._uuid) else ObjectId()
        item._uuid = str(_id)
        operations.append(
            UpdateOne(
                {'_id': _id},
                {'$set': update},
                upsert=True
            )
        )

    if operations:
        result = db.findings.bulk_write(operations, ordered=False)

    return items

# update_runner stays SYNC (needs immediate ID for context)
def update_runner(self):
    # ... unchanged ...
```

### Configuration

New config options:

```yaml
runners:
  async_hook_pool_size: 4
  async_hook_default_batch_size: 100
  async_hook_default_batch_interval: 5.0

addons:
  mongodb:
    batch_size: 100
    batch_interval: 5.0
```

Configuration resolution priority:
1. Hook-specific config in module's `BATCH_CONFIG` dict
2. Global defaults from `CONFIG.runners.async_hook_*`

### Error Handling

- Errors in async hooks are caught and collected (not raised)
- All errors returned from `flush_all()` at runner completion
- Errors added to `runner.errors` for reporting
- Each error includes hook name and batch size for debugging

### Flush Triggers

Batches are flushed when either condition is met:
1. **Batch size reached:** Number of items in queue >= `batch_size`
2. **Time interval passed:** `batch_interval` seconds since first item added

On runner completion, `flush_all()` is called to ensure all pending items are processed.

### Deduplication

Items are deduplicated by `_uuid` within a batch:
- If the same finding is updated multiple times during a batch window, only the latest version is kept
- Reduces redundant database operations

## Testing Strategy

Test file: `tests/unit/test_async_hooks.py`

Using `unittest` framework to match existing patterns:

- `TestBatchQueue`: add, deduplication, drain, batch_size trigger
- `TestAsyncHookManager`: submit, flush, error collection, shutdown
- `TestRunnerAsyncIntegration`: sync unchanged, async detection, finalize flush

Integration test: `tests/integration/test_async_mongodb.py`

- Verify bulk_write called with correct operations
- Test batch timing behavior
- Verify runner completion waits for persistence

## Files to Create/Modify

| File | Action | Description |
|------|--------|-------------|
| `secator/runners/_async.py` | Create | AsyncHookManager, BatchQueue |
| `secator/runners/_base.py` | Modify | Async hook detection, manager integration |
| `secator/hooks/mongodb.py` | Modify | Async update_finding with bulk upsert |
| `secator/config.py` | Modify | Add async hook config options |
| `tests/unit/test_async_hooks.py` | Create | Unit tests |
| `tests/integration/test_async_mongodb.py` | Create | Integration tests |

## Backward Compatibility

- Existing sync hooks work exactly as before
- Only `async def` hooks get the new behavior
- No changes to hook registration API
- `update_runner` remains synchronous

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Thread safety issues | Use locks in BatchQueue, thread-safe collections |
| Lost findings on crash | Configurable flush interval (lower = less risk) |
| Memory growth | Configurable batch size limits queue growth |
| Serialization issues | Async hooks run in thread pool, not separate process |
