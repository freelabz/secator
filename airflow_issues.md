# Airflow 3.0.6 + Python 3.14 — Upstream Compatibility Issues

Issues discovered while integrating secator with Apache Airflow 3.0.6 on Python 3.14.2.

---

## Issue 1: `TypeError: descriptor '__getitem__' requires a 'typing.Union' object` on Python 3.14

| | |
|---|---|
| **Repo** | [zmievsa/cadwyn](https://github.com/zmievsa/cadwyn) |
| **Existing issue** | **None** — not yet reported upstream |

**Environment:**
- Python 3.14.2
- cadwyn 5.4.6 (also affects 6.0.1, all 5.x/6.x)
- fastapi 0.117.1
- apache-airflow 3.0.6

**Description:**

When running Airflow 3.0.6's API server (which uses cadwyn for API versioning),
all requests to routes with `UnionType` annotations fail with:

```
File "cadwyn/schema_generation.py", line 620, in _change_version_of_a_non_container_annotation
    return getitem(
        tuple(self.change_version_of_annotation(a) for a in get_args(annotation)),
    )
TypeError: descriptor '__getitem__' requires a 'typing.Union' object but received a 'tuple'
```

The crash occurs in `schema_generation.py` line 619-622 where `typing.Union.__getitem__`
is extracted and called as a standalone function:

```python
getitem = typing.Union.__getitem__
return getitem(tuple(...))
```

Python 3.14 changed `typing.Union.__getitem__` to a descriptor. Calling it with a
tuple directly raises `TypeError` — it now requires being invoked on a `Union` instance,
not as a standalone function.

**Full traceback** (Airflow standalone log when the scheduler dispatches a task via
the internal execution API `/execution/task-instances/.../run`):

```
api-server | + Exception Group Traceback (most recent call last):
api-server | |     raise BaseExceptionGroup(
api-server | |         "unhandled errors in a TaskGroup", self._exceptions
api-server | | ExceptionGroup: unhandled errors in a TaskGroup (1 sub-exception)
api-server | | Traceback (most recent call last):
api-server | |   File ".../starlette/middleware/errors.py", line 186, in __call__
api-server | |   File ".../starlette/middleware/errors.py", line 164, in __call__
api-server | |     await self.app(scope, receive_or_disconnect, send_no_error)
api-server | |   File ".../starlette/middleware/exceptions.py", line 63, in __call__
api-server | |     await wrap_app_handling_exceptions(self.app, conn)(scope, receive, send)
api-server | |   File ".../starlette/_exception_handler.py", line 53, in wrapped_app
api-server | |   File ".../starlette/_exception_handler.py", line 42, in wrapped_app
api-server | |   File ".../cadwyn/schema_generation.py", line 620, in _change_version_of_a_non_container_annotation
api-server | |     return getitem(
api-server | |         tuple(self.change_version_of_annotation(a) for a in get_args(annotation)),
api-server | |     )
api-server | | TypeError: descriptor '__getitem__' requires a 'typing.Union' object but received a 'tuple'
```

On the scheduler side, this manifests as a 500 error and the task silently fails:

```
scheduler  | httpx.HTTPStatusError: Server error '500 Internal Server Error' for url
             'http://localhost:8080/execution/task-instances/<uuid>/run'

scheduler  | ERROR - Executor LocalExecutor(parallelism=32) reported that the task instance
             <TaskInstance: secator_task_httpx.httpx manual__... [queued]> finished with
             state failed, but the task instance's state attribute is queued.
```

**Reproduction:**

```python
import typing
getitem = typing.Union.__getitem__
getitem((int, str))  # TypeError on Python 3.14

# Works fine on Python <= 3.13
# Fails on Python >= 3.14
```

**Fix:**

Use the subscript syntax directly: `typing.Union[tuple(...)]`.

```python
# Before (broken on 3.14):
getitem = typing.Union.__getitem__
return getitem(tuple(self.change_version_of_annotation(a) for a in get_args(annotation)))

# After (works on all versions):
return typing.Union[tuple(self.change_version_of_annotation(a) for a in get_args(annotation))]
```

**Patch:**

```diff
--- a/cadwyn/schema_generation.py
+++ b/cadwyn/schema_generation.py
@@ -616,10 +616,7 @@
                 use_cache=annotation.use_cache,
             )
         elif isinstance(annotation, UnionType):  # pragma: no cover
-            getitem = typing.Union.__getitem__  # pyright: ignore[reportAttributeAccessIssue]
-            return getitem(
-                tuple(self.change_version_of_annotation(a) for a in get_args(annotation)),
-            )
+            return typing.Union[tuple(self.change_version_of_annotation(a) for a in get_args(annotation))]
         elif is_any(annotation) or is_newtype(annotation):
             return annotation
```

---

## Issue 2: `AttributeError: '_CallableWrapper' object has no attribute '__annotations__'` on Python 3.14

| | |
|---|---|
| **Repo** | [zmievsa/cadwyn](https://github.com/zmievsa/cadwyn) |
| **Existing issue** | **None** — can be reported together with Issue 1 |

**Environment:**
- Python 3.14.2
- cadwyn 5.4.6 (also affects 6.0.1, all 5.x/6.x)
- fastapi 0.117.1
- apache-airflow 3.0.6

**Description:**

On Python 3.14, cadwyn's `_modify_callable_annotations` method crashes when
accessing `annotation_modifying_wrapper.__annotations__`:

```
File "cadwyn/schema_generation.py", line 668, in _modify_callable_annotations
    callable_annotations = annotation_modifying_wrapper.__annotations__
                           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
AttributeError: '_CallableWrapper' object has no attribute '__annotations__'.
    Did you mean: '__annotate__'?
```

Python 3.14 implements PEP 749 (deferred evaluation of annotations), which means
`__annotations__` is no longer eagerly populated on all objects. The `_CallableWrapper`
object created by `_copy_function_through_class_based_wrapper` does not have
`__annotations__`, only `__annotate__`.

**Full traceback** (appears after patching Issue 1, on the same
`/execution/task-instances/.../run` endpoint):

```
api-server | Traceback (most recent call last):
api-server |   File ".../cadwyn/schema_generation.py", line 579, in migrate_route_to_version
api-server |     route.endpoint = self.change_version_of_annotation(route.endpoint)
api-server |   File ".../cadwyn/schema_generation.py", line 561, in change_version_of_annotation
api-server |     return self._change_version_of_a_non_container_annotation(annotation)
api-server |   File ".../cadwyn/schema_generation.py", line 633, in _change_version_of_a_non_container_annotation
api-server |     return self._modify_callable_annotations(
api-server |         annotation,
api-server |         ...
api-server |         annotation_modifying_wrapper_factory=self._copy_function_through_class_based_wrapper,
api-server |     )
api-server |   File ".../cadwyn/schema_generation.py", line 668, in _modify_callable_annotations
api-server |     callable_annotations = annotation_modifying_wrapper.__annotations__
api-server |                            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
api-server | AttributeError: '_CallableWrapper' object has no attribute '__annotations__'.
api-server |     Did you mean: '__annotate__'?
```

Again results in a 500 on the scheduler side:

```
scheduler  | httpx.HTTPStatusError: Server error '500 Internal Server Error' for url
             'http://localhost:8080/execution/task-instances/<uuid>/run'

scheduler  | ERROR - Executor LocalExecutor(parallelism=32) reported that the task instance
             <TaskInstance: secator_task_httpx.httpx manual__... [queued]> finished with
             state failed, but the task instance's state attribute is queued.
```

**Fix:**

Use `inspect.get_annotations()` (available since Python 3.10) which correctly
handles both the old and new annotation systems:

```python
# Before (broken on 3.14):
callable_annotations = annotation_modifying_wrapper.__annotations__

# After (works on all versions):
callable_annotations = (
    inspect.get_annotations(annotation_modifying_wrapper)
    if hasattr(inspect, 'get_annotations')
    else getattr(annotation_modifying_wrapper, '__annotations__', {})
)
```

**Patch:**

```diff
--- a/cadwyn/schema_generation.py
+++ b/cadwyn/schema_generation.py
@@ -665,7 +665,10 @@
     ) -> _Call:
         annotation_modifying_wrapper = annotation_modifying_wrapper_factory(call)
         old_params = inspect.signature(call).parameters
-        callable_annotations = annotation_modifying_wrapper.__annotations__
+        callable_annotations = (
+            inspect.get_annotations(annotation_modifying_wrapper)
+            if hasattr(inspect, 'get_annotations')
+            else getattr(annotation_modifying_wrapper, '__annotations__', {})
+        )
         callable_annotations = {
             k: v if type(v) is not str else _try_eval_type(v, call.__globals__) for k, v in callable_annotations.items()
         }
```

---

## Issue 3: httpx — `HTTPStatusError` is not pickleable

| | |
|---|---|
| **Library** | httpx 0.28.1 (current latest, all recent versions) |
| **Python** | Any version |
| **Triggered by** | Airflow LocalExecutor / CeleryExecutor multiprocessing queue |
| **Existing issue** | [encode/httpx#3345](https://github.com/encode/httpx/issues/3345) (OPEN, Oct 2024) |
| **Existing PR** | [encode/httpx#3346](https://github.com/encode/httpx/pull/3346) (OPEN, unreviewed for 16 months) |
| **Related Airflow** | [apache/airflow#42790](https://github.com/apache/airflow/issues/42790), [apache/airflow#47873](https://github.com/apache/airflow/issues/47873) |
| **Repo** | [encode/httpx](https://github.com/encode/httpx) |

### Full Traceback

When Airflow's LocalExecutor tries to send task results through its multiprocessing
queue, the scheduler crashes trying to pickle the `httpx.HTTPStatusError` exception.
The scheduler log shows:

```
scheduler  | File ".../airflow/sdk/api/client.py", line 152, in start
scheduler  | File ".../httpx/_client.py", line 1218, in patch
scheduler  | File ".../tenacity/__init__.py", line 331, in wrapped_f
scheduler  | File ".../tenacity/__init__.py", line 470, in __call__
scheduler  | File ".../tenacity/__init__.py", line 371, in iter
scheduler  | File ".../tenacity/__init__.py", line 413, in exc_check
scheduler  | File ".../tenacity/__init__.py", line 184, in reraise
scheduler  |     raise self._exception
scheduler  | File ".../tenacity/__init__.py", line 473, in __call__
scheduler  | File ".../airflow/sdk/api/client.py", line 735, in request
scheduler  | File ".../httpx/_client.py", line 825, in request
scheduler  | File ".../httpx/_client.py", line 914, in send
scheduler  | File ".../httpx/_client.py", line 942, in _send_handling_auth
scheduler  | File ".../httpx/_client.py", line 999, in _send_handling_redirects
scheduler  | File ".../httpx/_client.py", line 982, in _send_handling_redirects
scheduler  | File ".../airflow/sdk/api/client.py", line 123, in raise_on_4xx_5xx_with_note
scheduler  |     return get_json_error(response) or response.raise_for_status()
scheduler  | File ".../httpx/_models.py", line 829, in raise_for_status
scheduler  |     raise HTTPStatusError(message, request=request, response=self)
scheduler  | httpx.HTTPStatusError: Server error '500 Internal Server Error' for url
             'http://localhost:8080/execution/task-instances/<uuid>/run'
```

The LocalExecutor then reports the mismatch:

```
scheduler  | [local_executor.py:96] ERROR - uhoh

scheduler  | ERROR - Executor LocalExecutor(parallelism=32) reported that the task instance
             <TaskInstance: secator_task_httpx.httpx manual__... [queued]> finished with
             state failed, but the task instance's state attribute is queued. Learn more:
             https://airflow.apache.org/docs/apache-airflow/stable/troubleshooting.html
             #task-state-changed-externally
```

The task log files are **empty** (0 bytes) because the worker crashes before writing
any output. The task stays in "queued" state from the task instance's perspective,
even though the executor reported it as "failed".

### Reproduction

```python
import httpx, pickle

exc = httpx.HTTPStatusError(
    'test',
    request=httpx.Request('GET', 'http://x'),
    response=httpx.Response(500)
)
pickle.dumps(exc)  # TypeError: HTTPStatusError.__init__() missing required keyword-only arguments
```

### Root Cause

`HTTPStatusError.__init__` has keyword-only arguments (`request`, `response`) that
are not captured in `Exception.args`. When `pickle` reconstructs the exception, it
only has the message string from `args`, and calling `HTTPStatusError(message)` fails
because the required `request` and `response` kwargs are missing.

This was originally fixed in [PR #2062](https://github.com/encode/httpx/pull/2062) (2022)
by passing kwargs to `super().__init__()`, but that approach **regressed**.
[PR #3346](https://github.com/encode/httpx/pull/3346) has the correct fix using
`__reduce__`/`__setstate__` but has been open and unreviewed since October 2024.

In Airflow, this causes the scheduler to crash silently when sending task results
through the LocalExecutor multiprocessing queue. The observable symptom is:
- Task log files are 0 bytes (empty)
- Task stays in "queued" state indefinitely
- Scheduler reports the state mismatch error shown above

### Patch

```diff
--- a/httpx/_exceptions.py
+++ b/httpx/_exceptions.py
@@ -241,6 +241,17 @@
         self.request = request
         self.response = response

+    def __reduce__(self) -> tuple:
+        return (
+            self.__class__,
+            (str(self),),
+            {"request": self.request, "response": self.response},
+        )
+
+    def __setstate__(self, state: dict) -> None:
+        self.request = state["request"]
+        self.response = state["response"]
+

 class InvalidURL(Exception):
```

---

## Issue 4: FastAPI / Cadwyn version conflict with Airflow 3.0.6

| | |
|---|---|
| **Type** | Packaging / dependency conflict (not a bug to file) |
| **Conflict** | Airflow 3.0.6 requires `fastapi<0.118`; Cadwyn 6.0.1 requires `fastapi>=0.121.1` |

### Error

When installing `apache-airflow` with the default cadwyn version (6.0.1), pip reports:

```
ERROR: pip's dependency resolver does not currently take into account all the
packages that are installed. This behaviour is the source of the following
dependency conflicts.
cadwyn 6.0.1 requires fastapi>=0.121.1, but you have fastapi 0.117.1 which
is incompatible.
```

And running `airflow db migrate` after installing cadwyn 6.0.1 fails with:

```
ImportError: cannot import name 'get_compat_model_name_map' from 'fastapi._compat'
```

### Resolution

Pin cadwyn to `<6` to get version 5.4.6, which accepts `fastapi>=0.112.4`:

```bash
pip install 'apache-airflow>=3.0,<4' 'cadwyn<6' 'fastapi<0.118'
```

---

## Automated Fix

All patches above are applied automatically by:

```bash
secator worker --backend airflow --init
```

This command installs Airflow with compatible dependency pins, runs database migration,
deploys DAG entry points, applies the cadwyn and httpx patches, and starts the Airflow
standalone cluster.
