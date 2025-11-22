# Event Triggers Feature

## Overview

Event triggers allow workflows to automatically spawn tasks when specific output items match certain conditions. Items are batched and tasks are triggered either when the batch reaches a specified size or after a timeout period.

## Implementation Summary

### Core Components

1. **Runner Base Class (`secator/runners/_base.py`)**
   - Added event trigger state management with lazy-initialized RLock for thread safety
   - Implemented `register_event_trigger()` to register triggers
   - Implemented `_check_event_triggers()` to match items against triggers
   - Implemented batching with count and time-based triggering
   - Implemented `_trigger_event_task()` base method (overridden in Workflow)
   - Added `cancel_event_timers()` for cleanup

2. **Workflow Class (`secator/runners/workflow.py`)**
   - Modified `process_task()` to recognize `on_event` configuration
   - Overrode `_trigger_event_task()` to actually spawn tasks with batched items
   - Integrated with existing `targets_` mechanism for input extraction

3. **Configuration Format**
   ```yaml
   tasks:
     task_name:
       on_event:
         type: url                          # Output type to watch
         condition: item.status_code == 403 # Optional condition
         batch_size: 5                      # Items to batch
         batch_timeout: 30                  # Timeout in seconds
       targets_:
         - type: url
           field: url
   ```

### Key Features

- **Lazy Initialization**: Threading objects use lazy initialization to maintain serializability for Celery
- **Reentrant Lock**: Uses `threading.RLock()` to avoid deadlocks in nested lock scenarios
- **Batching**: Two-mode batching - count-based and time-based
- **Condition Evaluation**: Safely evaluates Python expressions with restricted builtins
- **Input Extraction**: Reuses existing `targets_` mechanism for extracting inputs from batched items
- **Thread Safety**: All batch operations protected by reentrant lock
- **Timer Cleanup**: Automatic cancellation of pending timers on workflow completion

### Example Workflow

See `secator/configs/workflows/url_bypass_auto.yaml` for a complete example that:
1. Probes URLs with httpx
2. Automatically triggers bup when 403 status codes are found
3. Batches up to 5 URLs or waits 30 seconds before triggering

### Tests

- **Unit Tests** (`tests/unit/test_event_triggers.py`): 6 tests covering:
  - Event trigger registration
  - Item matching and batching
  - Batch size triggering
  - Lock lazy initialization
  - Timer cancellation

- **Integration Tests** (`tests/integration/test_event_triggers_integration.py`):
  - Workflow-level event trigger registration

All tests passing ✓

## Usage

```python
from secator.runners import Workflow
from secator.template import TemplateLoader

# Load workflow with event triggers
config = TemplateLoader(name='workflow/url_bypass_auto')
workflow = Workflow(config, inputs=['http://example.com'], run_opts={'sync': True})
results = workflow.run()
```

Or via CLI:
```bash
secator workflow url_bypass_auto http://example.com
```

## Technical Decisions

1. **RLock vs Lock**: Chose RLock to handle cases where `_trigger_event_task` is called while holding the lock
2. **Lazy Initialization**: Required for Celery serialization of Runner instances
3. **Synchronous Execution**: Triggered tasks run synchronously within the workflow for simplicity
4. **No Nested Triggers**: Event-triggered tasks cannot themselves use event triggers (limitation noted in docs)

## Future Enhancements

- Async task spawning for better performance
- Support for event triggers in Scans
- Nested event trigger support
- Event trigger metrics and monitoring
- Conditional task cancellation
