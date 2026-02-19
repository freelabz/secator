# Async Hooks Implementation Results

**Date:** 2026-02-19
**Status:** Complete (pending merge)
**Branch:** `batch-updates`
**Base:** `main` (2a34a9a)

## Summary

Implemented an async hook system for secator that enables non-blocking hook execution with batching support. This reduces MongoDB pressure by batching `update_finding` calls instead of writing each finding individually.

## Problem Solved

The original hook system was synchronous - hooks blocked execution while running. For I/O-heavy hooks like MongoDB updates, this created performance bottlenecks:
- `update_finding` called for every finding, blocking the runner
- High-frequency MongoDB calls put pressure on the database
- No batching mechanism for bulk operations

## Solution Implemented

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

### Key Features

1. **Async Hook Detection**: Hooks marked via `ASYNC_HOOKS` set in module or `async def` syntax
2. **Batching**: Items collected into batches before execution
3. **Deduplication**: Items with same `_uuid` deduplicated (latest wins)
4. **Configurable Triggers**: Flush on batch_size OR batch_interval
5. **Thread Pool Execution**: Non-blocking execution via ThreadPoolExecutor
6. **Error Collection**: Errors collected and reported at runner completion
7. **Graceful Shutdown**: All pending batches flushed before runner exits

## Tasks Completed

| Task | Description | Status |
|------|-------------|--------|
| 1 | Add Configuration Options | Completed |
| 2 | Create BatchQueue Class | Completed |
| 3 | Create AsyncHookManager Class | Completed |
| 4 | Integrate AsyncHookManager into Runner | Completed |
| 5 | Migrate MongoDB update_finding to Async | Completed |
| 6 | Add Integration Test | Completed |
| 7 | Final Verification and Cleanup | Completed |

## Files Changed

### New Files

| File | Lines | Description |
|------|-------|-------------|
| `secator/runners/_async.py` | 253 | AsyncHookManager and BatchQueue classes |
| `tests/unit/test_async_hooks.py` | 156 | Unit tests for BatchQueue and AsyncHookManager |
| `tests/unit/test_mongodb_async.py` | 96 | Unit tests for MongoDB async hooks |
| `tests/integration/test_async_mongodb.py` | 278 | Integration tests |

### Modified Files

| File | Changes | Description |
|------|---------|-------------|
| `secator/config.py` | +5 lines | Added async hook config options |
| `secator/runners/_base.py` | +61 lines | Runner integration |
| `secator/hooks/mongodb.py` | +55/-30 lines | Batch update_finding |

## Configuration Options Added

```yaml
runners:
  async_hook_pool_size: 4          # Thread pool size
  async_hook_default_batch_size: 100    # Default batch size
  async_hook_default_batch_interval: 5.0  # Default interval (seconds)

addons:
  mongodb:
    batch_size: 100      # MongoDB-specific batch size
    batch_interval: 5.0  # MongoDB-specific interval
```

## Commits

```
c1273bd test(integration): add async MongoDB hook integration tests
fa11e15 feat(mongodb): migrate update_finding to async batch execution
4c570de feat(runner): integrate AsyncHookManager for async hook execution
9e985ca feat(async): add AsyncHookManager with thread pool and batching
7251c96 feat(async): add BatchQueue class with deduplication
2cf82b0 feat(config): add async hook configuration options
```

## Test Results

**28 tests passing:**
- Unit tests (BatchQueue): 4 tests
- Unit tests (AsyncHookManager): 4 tests
- Unit tests (Runner integration): 2 tests
- Unit tests (MongoDB): 6 tests
- Integration tests: 12 tests

## Usage Example

To mark a hook for async batch execution:

```python
# In your hooks module (e.g., secator/hooks/mongodb.py)

# 1. Define batch configuration
BATCH_CONFIG = {
    'update_finding': {
        'batch_size': CONFIG.addons.mongodb.batch_size,
        'batch_interval': CONFIG.addons.mongodb.batch_interval
    }
}

# 2. Mark hooks for async execution
ASYNC_HOOKS = {'update_finding'}

# 3. Write hook to accept list of items
def update_finding(self, items):
    """Batch upsert findings to MongoDB."""
    if not items:
        return items

    # Handle single item for backward compatibility
    if not isinstance(items, list):
        items = [items]

    # Use bulk operations
    operations = [UpdateOne({'_id': id}, {'$set': data}, upsert=True)
                  for item in items]
    db.findings.bulk_write(operations, ordered=False)

    return items
```

## Backward Compatibility

- Existing sync hooks work exactly as before
- Only hooks in `ASYNC_HOOKS` set get batched execution
- `update_runner` remains synchronous (needs immediate context ID)
- Single-item calls still work (converted to list internally)

## Review Notes

The implementation was reviewed at each task with:
- Spec compliance review (verified implementation matches design)
- Code quality review (verified code quality and best practices)
- Final review (verified complete implementation)

### Minor Recommendations from Reviews

1. Consider adding timer-based flush test
2. Consider moving `from pymongo import UpdateOne` to module level
3. Consider periodic cleanup of completed futures in long-running processes

These are non-blocking suggestions for future improvement.

## Next Steps

The branch is ready for merge when you're ready:

```bash
# Option 1: Merge locally
git checkout main
git merge batch-updates
git branch -d batch-updates

# Option 2: Create PR
git push -u origin batch-updates
gh pr create --title "feat: async hooks with batching for MongoDB" --body "..."
```
