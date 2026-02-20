# AI Workspace Query Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enable AI task to query workspace results via natural language prompts with pluggable query backends.

**Architecture:** Two-phase LLM (intent analysis + execution) with pluggable query backends (API, MongoDB, JSON). Safety flags for destructive/aggressive commands in attack mode.

**Tech Stack:** Python, LiteLLM, pymongo (optional), pytest

---

## Task 1: Configuration Changes

**Files:**
- Modify: `secator/config.py:210-230`
- Test: `tests/unit/test_config.py`

**Step 1: Write the failing test**

```python
# tests/unit/test_config.py - add at end of file

class TestAIConfig(unittest.TestCase):

    def test_ai_config_defaults(self):
        from secator.config import Config
        config = Config.parse()
        self.assertIsNotNone(config.ai)
        self.assertEqual(config.ai.default_model, 'gpt-4o-mini')
        self.assertEqual(config.ai.intent_model, 'gpt-4o-mini')
        self.assertEqual(config.ai.max_results, 500)
        self.assertEqual(config.ai.encrypt_pii, True)

    def test_api_finding_search_endpoint(self):
        from secator.config import Config
        config = Config.parse()
        self.assertEqual(config.addons.api.finding_search_endpoint, 'findings/_search')
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_config.py::TestAIConfig -v`
Expected: FAIL with "AttributeError: 'Config' object has no attribute 'ai'"

**Step 3: Write minimal implementation**

```python
# secator/config.py - add after VulnersAddon class (around line 200)

class AI(StrictModel):
    """AI task configuration."""
    default_model: str = 'gpt-4o-mini'
    intent_model: str = 'gpt-4o-mini'
    execution_model: str = 'gpt-4o-mini'
    temperature: float = 0.7
    max_tokens: int = 4096
    max_results: int = 500
    encrypt_pii: bool = True
```

```python
# secator/config.py - modify ApiAddon class (around line 210)
class ApiAddon(StrictModel):
    enabled: bool = False
    url: str = 'https://app.secator.cloud/api'
    key: str = ''
    header_name: str = 'Bearer'
    force_ssl: bool = True
    runner_create_endpoint: str = 'runners'
    runner_update_endpoint: str = 'runner/{runner_id}'
    finding_create_endpoint: str = 'findings'
    finding_update_endpoint: str = 'finding/{finding_id}'
    finding_search_endpoint: str = 'findings/_search'  # NEW
    workspace_get_endpoint: str = 'workspace/{workspace_id}'
```

```python
# secator/config.py - modify SecatorConfig class (around line 232)
class SecatorConfig(StrictModel):
    debug: str = ''
    dirs: Directories = Directories()
    celery: Celery = Celery()
    cli: Cli = Cli()
    runners: Runners = Runners()
    http: HTTP = HTTP()
    tasks: Tasks = Tasks()
    workflows: Workflows = Workflows()
    scans: Scans = Scans()
    payloads: Payloads = Payloads()
    wordlists: Wordlists = Wordlists()
    profiles: Profiles = Profiles()
    drivers: Drivers = Drivers()
    addons: Addons = Addons()
    security: Security = Security()
    providers: Providers = Providers()
    offline_mode: bool = False
    ai: AI = AI()  # NEW
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_config.py::TestAIConfig -v`
Expected: PASS

**Step 5: Commit**

```bash
git add secator/config.py tests/unit/test_config.py
git commit -m "feat(config): add AI config and finding_search_endpoint"
```

---

## Task 2: Query Backend Base Class

**Files:**
- Create: `secator/query/__init__.py`
- Create: `secator/query/_base.py`
- Test: `tests/unit/test_query.py`

**Step 1: Create directory and write failing test**

```bash
mkdir -p secator/query
touch secator/query/__init__.py
```

```python
# tests/unit/test_query.py

import unittest


class TestQueryBackendBase(unittest.TestCase):

    def test_base_query_includes_workspace_id(self):
        from secator.query._base import QueryBackend
        # Can't instantiate abstract class, so test via concrete implementation
        # For now just test the module imports
        self.assertTrue(hasattr(QueryBackend, 'PROTECTED_FIELDS'))
        self.assertIn('_context.workspace_id', QueryBackend.PROTECTED_FIELDS)

    def test_merge_query_enforces_base(self):
        from secator.query._base import QueryBackend

        class TestBackend(QueryBackend):
            name = "test"
            def _execute_search(self, query, limit):
                return []
            def count(self, query):
                return 0

        backend = TestBackend(workspace_id='ws123')

        # Try to override protected field
        user_query = {
            '_type': 'vulnerability',
            '_context.workspace_id': 'malicious_id'
        }

        merged = backend._merge_query(user_query)

        # Protected field should be enforced
        self.assertEqual(merged['_context.workspace_id'], 'ws123')
        self.assertEqual(merged['_type'], 'vulnerability')
        self.assertEqual(merged['is_false_positive'], False)

    def test_merge_query_preserves_user_fields(self):
        from secator.query._base import QueryBackend

        class TestBackend(QueryBackend):
            name = "test"
            def _execute_search(self, query, limit):
                return []
            def count(self, query):
                return 0

        backend = TestBackend(workspace_id='ws123')

        user_query = {
            '_type': 'url',
            'severity': {'$in': ['critical', 'high']},
            'url': {'$contains': 'login'}
        }

        merged = backend._merge_query(user_query)

        self.assertEqual(merged['_type'], 'url')
        self.assertEqual(merged['severity'], {'$in': ['critical', 'high']})
        self.assertEqual(merged['url'], {'$contains': 'login'})
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_query.py -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'secator.query._base'"

**Step 3: Write minimal implementation**

```python
# secator/query/_base.py

from abc import ABC, abstractmethod
from typing import List, Dict, Any


class QueryBackend(ABC):
    """Abstract base class for query backends."""

    name: str = "base"

    PROTECTED_FIELDS = [
        "_context.workspace_id",
        "_context.workspace_duplicate",
    ]

    def __init__(self, workspace_id: str, config: dict = None):
        self.workspace_id = workspace_id
        self.config = config or {}

    def get_base_query(self) -> dict:
        """Base query - ALWAYS enforced, cannot be overridden."""
        return {
            "_context.workspace_id": self.workspace_id,
            "_context.workspace_duplicate": False,
            "is_false_positive": False
        }

    def _merge_query(self, query: dict) -> dict:
        """Merge user query with base query. Base query always wins."""
        merged = query.copy()

        for field in self.PROTECTED_FIELDS:
            if field in merged:
                del merged[field]

        base = self.get_base_query()
        merged.update(base)

        return merged

    def search(self, query: dict, limit: int = 100) -> List[Dict[str, Any]]:
        """Execute query with enforced base query."""
        safe_query = self._merge_query(query)
        return self._execute_search(safe_query, limit)

    @abstractmethod
    def _execute_search(self, query: dict, limit: int) -> List[Dict[str, Any]]:
        """Backend-specific search implementation."""
        pass

    @abstractmethod
    def count(self, query: dict) -> int:
        """Count matching findings."""
        pass
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_query.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add secator/query/ tests/unit/test_query.py
git commit -m "feat(query): add abstract QueryBackend base class"
```

---

## Task 3: JSON Query Backend

**Files:**
- Create: `secator/query/json.py`
- Test: `tests/unit/test_query.py` (add tests)

**Step 1: Write the failing test**

```python
# tests/unit/test_query.py - add to file

import tempfile
import json
from pathlib import Path


class TestJsonBackend(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.workspace_id = 'test_workspace'
        self.workspace_dir = Path(self.temp_dir) / self.workspace_id / 'tasks' / '0'
        self.workspace_dir.mkdir(parents=True)

        # Create test report.json
        self.test_data = {
            "info": {"name": "test"},
            "results": {
                "vulnerability": [
                    {
                        "_type": "vulnerability",
                        "name": "SQL Injection",
                        "severity": "critical",
                        "matched_at": "http://example.com/login",
                        "is_false_positive": False,
                        "_context": {
                            "workspace_id": self.workspace_id,
                            "workspace_duplicate": False
                        }
                    },
                    {
                        "_type": "vulnerability",
                        "name": "XSS",
                        "severity": "medium",
                        "matched_at": "http://example.com/search",
                        "is_false_positive": False,
                        "_context": {
                            "workspace_id": self.workspace_id,
                            "workspace_duplicate": False
                        }
                    }
                ],
                "url": [
                    {
                        "_type": "url",
                        "url": "http://example.com/login",
                        "status_code": 200,
                        "is_false_positive": False,
                        "_context": {
                            "workspace_id": self.workspace_id,
                            "workspace_duplicate": False
                        }
                    }
                ]
            }
        }

        with open(self.workspace_dir / 'report.json', 'w') as f:
            json.dump(self.test_data, f)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir)

    def test_json_backend_search_by_type(self):
        from secator.query.json import JsonBackend

        backend = JsonBackend(
            workspace_id=self.workspace_id,
            config={'reports_dir': self.temp_dir}
        )

        results = backend.search({'_type': 'vulnerability'})

        self.assertEqual(len(results), 2)
        self.assertTrue(all(r['_type'] == 'vulnerability' for r in results))

    def test_json_backend_search_with_operator(self):
        from secator.query.json import JsonBackend

        backend = JsonBackend(
            workspace_id=self.workspace_id,
            config={'reports_dir': self.temp_dir}
        )

        results = backend.search({
            '_type': 'vulnerability',
            'severity': {'$in': ['critical', 'high']}
        })

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['name'], 'SQL Injection')

    def test_json_backend_search_contains(self):
        from secator.query.json import JsonBackend

        backend = JsonBackend(
            workspace_id=self.workspace_id,
            config={'reports_dir': self.temp_dir}
        )

        results = backend.search({
            '_type': 'vulnerability',
            'matched_at': {'$contains': 'login'}
        })

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['name'], 'SQL Injection')

    def test_json_backend_count(self):
        from secator.query.json import JsonBackend

        backend = JsonBackend(
            workspace_id=self.workspace_id,
            config={'reports_dir': self.temp_dir}
        )

        count = backend.count({'_type': 'vulnerability'})
        self.assertEqual(count, 2)


class TestQueryOperators(unittest.TestCase):

    def test_get_nested_field(self):
        from secator.query.json import get_nested_field

        item = {
            '_context': {
                'workspace_id': 'ws123',
                'nested': {'deep': 'value'}
            },
            'name': 'test'
        }

        self.assertEqual(get_nested_field(item, 'name'), 'test')
        self.assertEqual(get_nested_field(item, '_context.workspace_id'), 'ws123')
        self.assertEqual(get_nested_field(item, '_context.nested.deep'), 'value')
        self.assertIsNone(get_nested_field(item, 'nonexistent'))

    def test_match_query_direct_match(self):
        from secator.query.json import match_query

        item = {'_type': 'url', 'status_code': 200}

        self.assertTrue(match_query(item, {'_type': 'url'}))
        self.assertTrue(match_query(item, {'status_code': 200}))
        self.assertFalse(match_query(item, {'_type': 'vulnerability'}))

    def test_match_query_operators(self):
        from secator.query.json import match_query

        item = {'severity': 'critical', 'cvss_score': 9.5, 'url': 'http://example.com/login'}

        # $in
        self.assertTrue(match_query(item, {'severity': {'$in': ['critical', 'high']}}))
        self.assertFalse(match_query(item, {'severity': {'$in': ['low', 'medium']}}))

        # $contains
        self.assertTrue(match_query(item, {'url': {'$contains': 'login'}}))
        self.assertFalse(match_query(item, {'url': {'$contains': 'admin'}}))

        # $gt, $gte, $lt, $lte
        self.assertTrue(match_query(item, {'cvss_score': {'$gt': 9.0}}))
        self.assertTrue(match_query(item, {'cvss_score': {'$gte': 9.5}}))
        self.assertFalse(match_query(item, {'cvss_score': {'$lt': 9.0}}))

        # $regex
        self.assertTrue(match_query(item, {'url': {'$regex': r'example\.com'}}))
        self.assertFalse(match_query(item, {'url': {'$regex': r'other\.com'}}))
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_query.py::TestJsonBackend -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'secator.query.json'"

**Step 3: Write minimal implementation**

```python
# secator/query/json.py

import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional

from secator.query._base import QueryBackend
from secator.config import CONFIG


OPERATORS = {
    "$regex": lambda field, pattern: re.search(pattern, str(field)) is not None if field else False,
    "$contains": lambda field, value: value in str(field) if field else False,
    "$startswith": lambda field, value: str(field).startswith(value) if field else False,
    "$in": lambda field, values: field in values if field else False,
    "$gt": lambda field, value: field > value if field is not None else False,
    "$gte": lambda field, value: field >= value if field is not None else False,
    "$lt": lambda field, value: field < value if field is not None else False,
    "$lte": lambda field, value: field <= value if field is not None else False,
    "$ne": lambda field, value: field != value,
}


def get_nested_field(item: dict, key: str) -> Any:
    """Get nested field value using dot notation (e.g., '_context.workspace_id')."""
    keys = key.split('.')
    value = item
    for k in keys:
        if isinstance(value, dict):
            value = value.get(k)
        else:
            return None
    return value


def match_query(item: dict, query: dict) -> bool:
    """Check if item matches MongoDB-style query."""
    for key, condition in query.items():
        value = get_nested_field(item, key)

        if isinstance(condition, dict):
            for op, op_value in condition.items():
                if op not in OPERATORS:
                    continue
                if not OPERATORS[op](value, op_value):
                    return False
        else:
            if value != condition:
                return False
    return True


class JsonBackend(QueryBackend):
    """Query backend for JSON files on filesystem."""

    name = "json"

    def __init__(self, workspace_id: str, config: dict = None):
        super().__init__(workspace_id, config)
        self.reports_dir = Path(config.get('reports_dir', CONFIG.dirs.reports)) if config else CONFIG.dirs.reports

    def _get_workspace_path(self) -> Path:
        """Get path to workspace reports directory."""
        return self.reports_dir / self.workspace_id

    def _load_all_findings(self) -> List[Dict[str, Any]]:
        """Load all findings from workspace JSON files."""
        findings = []
        workspace_path = self._get_workspace_path()

        if not workspace_path.exists():
            return findings

        # Search for report.json files in tasks/, workflows/, scans/
        for runner_type in ['tasks', 'workflows', 'scans']:
            runner_path = workspace_path / runner_type
            if not runner_path.exists():
                continue

            for report_dir in runner_path.iterdir():
                if not report_dir.is_dir():
                    continue

                report_file = report_dir / 'report.json'
                if report_file.exists():
                    try:
                        with open(report_file, 'r') as f:
                            data = json.load(f)

                        results = data.get('results', {})
                        for type_name, items in results.items():
                            if isinstance(items, list):
                                findings.extend(items)
                    except (json.JSONDecodeError, IOError):
                        continue

        return findings

    def _execute_search(self, query: dict, limit: int = 100) -> List[Dict[str, Any]]:
        """Search findings matching query."""
        findings = self._load_all_findings()

        matched = []
        for finding in findings:
            if match_query(finding, query):
                matched.append(finding)
                if len(matched) >= limit:
                    break

        return matched

    def count(self, query: dict) -> int:
        """Count findings matching query."""
        safe_query = self._merge_query(query)
        findings = self._load_all_findings()
        return sum(1 for f in findings if match_query(f, safe_query))
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_query.py::TestJsonBackend tests/unit/test_query.py::TestQueryOperators -v`
Expected: PASS

**Step 5: Commit**

```bash
git add secator/query/json.py tests/unit/test_query.py
git commit -m "feat(query): add JSON filesystem query backend"
```

---

## Task 4: MongoDB Query Backend

**Files:**
- Create: `secator/query/mongodb.py`
- Test: `tests/unit/test_query.py` (add tests)

**Step 1: Write the failing test**

```python
# tests/unit/test_query.py - add to file

class TestMongoDBBackend(unittest.TestCase):

    def test_mongodb_backend_instantiation(self):
        from secator.query.mongodb import MongoDBBackend

        backend = MongoDBBackend(workspace_id='ws123')
        self.assertEqual(backend.workspace_id, 'ws123')
        self.assertEqual(backend.name, 'mongodb')

    def test_mongodb_backend_base_query_includes_tagged(self):
        from secator.query.mongodb import MongoDBBackend

        backend = MongoDBBackend(workspace_id='ws123')
        base = backend.get_base_query()

        self.assertEqual(base['_tagged'], True)
        self.assertEqual(base['_context.workspace_id'], 'ws123')
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_query.py::TestMongoDBBackend -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'secator.query.mongodb'"

**Step 3: Write minimal implementation**

```python
# secator/query/mongodb.py

from typing import List, Dict, Any

from secator.query._base import QueryBackend


class MongoDBBackend(QueryBackend):
    """Query backend for MongoDB."""

    name = "mongodb"

    def __init__(self, workspace_id: str, config: dict = None):
        super().__init__(workspace_id, config)
        self._client = None

    def get_base_query(self) -> dict:
        """Base query with _tagged for MongoDB."""
        base = super().get_base_query()
        base['_tagged'] = True
        return base

    def _get_client(self):
        """Get or create MongoDB client."""
        if self._client is None:
            from secator.hooks.mongodb import get_mongodb_client
            self._client = get_mongodb_client()
        return self._client

    def _execute_search(self, query: dict, limit: int = 100) -> List[Dict[str, Any]]:
        """Search MongoDB for findings matching query."""
        try:
            client = self._get_client()
            db = client.main

            cursor = db.findings.find(query).limit(limit)

            results = []
            for doc in cursor:
                doc['_id'] = str(doc['_id'])
                results.append(doc)

            return results
        except Exception:
            return []

    def count(self, query: dict) -> int:
        """Count findings matching query."""
        try:
            safe_query = self._merge_query(query)
            client = self._get_client()
            db = client.main
            return db.findings.count_documents(safe_query)
        except Exception:
            return 0
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_query.py::TestMongoDBBackend -v`
Expected: PASS

**Step 5: Commit**

```bash
git add secator/query/mongodb.py tests/unit/test_query.py
git commit -m "feat(query): add MongoDB query backend"
```

---

## Task 5: API Query Backend

**Files:**
- Create: `secator/query/api.py`
- Test: `tests/unit/test_query.py` (add tests)

**Step 1: Write the failing test**

```python
# tests/unit/test_query.py - add to file

class TestApiBackend(unittest.TestCase):

    def test_api_backend_instantiation(self):
        from secator.query.api import ApiBackend

        backend = ApiBackend(workspace_id='ws123')
        self.assertEqual(backend.workspace_id, 'ws123')
        self.assertEqual(backend.name, 'api')

    def test_api_backend_base_query_includes_tagged(self):
        from secator.query.api import ApiBackend

        backend = ApiBackend(workspace_id='ws123')
        base = backend.get_base_query()

        self.assertEqual(base['_tagged'], True)
        self.assertEqual(base['_context.workspace_id'], 'ws123')
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_query.py::TestApiBackend -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'secator.query.api'"

**Step 3: Write minimal implementation**

```python
# secator/query/api.py

import json
from typing import List, Dict, Any

import requests

from secator.query._base import QueryBackend
from secator.config import CONFIG


class ApiBackend(QueryBackend):
    """Query backend for remote API."""

    name = "api"

    def __init__(self, workspace_id: str, config: dict = None):
        super().__init__(workspace_id, config)
        self.api_url = CONFIG.addons.api.url
        self.api_key = CONFIG.addons.api.key
        self.header_name = CONFIG.addons.api.header_name
        self.search_endpoint = CONFIG.addons.api.finding_search_endpoint
        self.force_ssl = CONFIG.addons.api.force_ssl

    def get_base_query(self) -> dict:
        """Base query with _tagged for API."""
        base = super().get_base_query()
        base['_tagged'] = True
        return base

    def _make_request(self, method: str, endpoint: str, data: dict = None) -> dict:
        """Make HTTP request to API."""
        url = f"{self.api_url.rstrip('/')}/{endpoint.lstrip('/')}"
        headers = {"Content-Type": "application/json"}

        if self.api_key:
            headers["Authorization"] = f"{self.header_name} {self.api_key}"

        response = requests.request(
            method=method,
            url=url,
            data=json.dumps(data) if data else None,
            headers=headers,
            verify=self.force_ssl,
            timeout=30
        )
        response.raise_for_status()
        return response.json()

    def _execute_search(self, query: dict, limit: int = 100) -> List[Dict[str, Any]]:
        """Search API for findings matching query."""
        try:
            endpoint = f"{self.search_endpoint}?skip=0&limit={limit}"
            result = self._make_request('POST', endpoint, query)

            if isinstance(result, list):
                return result
            elif isinstance(result, dict) and 'items' in result:
                return result['items']
            elif isinstance(result, dict) and 'results' in result:
                return result['results']

            return []
        except Exception:
            return []

    def count(self, query: dict) -> int:
        """Count findings matching query."""
        try:
            safe_query = self._merge_query(query)
            endpoint = f"{self.search_endpoint}?skip=0&limit=0"
            result = self._make_request('POST', endpoint, safe_query)

            if isinstance(result, dict) and 'total' in result:
                return result['total']

            return 0
        except Exception:
            return 0
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_query.py::TestApiBackend -v`
Expected: PASS

**Step 5: Commit**

```bash
git add secator/query/api.py tests/unit/test_query.py
git commit -m "feat(query): add API query backend"
```

---

## Task 6: Query Engine

**Files:**
- Modify: `secator/query/__init__.py`
- Test: `tests/unit/test_query.py` (add tests)

**Step 1: Write the failing test**

```python
# tests/unit/test_query.py - add to file

class TestQueryEngine(unittest.TestCase):

    def test_query_engine_selects_json_by_default(self):
        from secator.query import QueryEngine
        from secator.query.json import JsonBackend

        engine = QueryEngine(workspace_id='ws123', context={})
        self.assertIsInstance(engine.backend, JsonBackend)

    def test_query_engine_selects_api(self):
        from secator.query import QueryEngine
        from secator.query.api import ApiBackend

        engine = QueryEngine(workspace_id='ws123', context={'api': True})
        self.assertIsInstance(engine.backend, ApiBackend)

    def test_query_engine_selects_mongodb(self):
        from secator.query import QueryEngine
        from secator.query.mongodb import MongoDBBackend

        engine = QueryEngine(workspace_id='ws123', context={'mongodb': True})
        self.assertIsInstance(engine.backend, MongoDBBackend)

    def test_query_engine_api_takes_priority(self):
        from secator.query import QueryEngine
        from secator.query.api import ApiBackend

        # When both are true, API takes priority
        engine = QueryEngine(workspace_id='ws123', context={'api': True, 'mongodb': True})
        self.assertIsInstance(engine.backend, ApiBackend)
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_query.py::TestQueryEngine -v`
Expected: FAIL with "ImportError: cannot import name 'QueryEngine'"

**Step 3: Write minimal implementation**

```python
# secator/query/__init__.py

from typing import List, Dict, Any

from secator.query._base import QueryBackend
from secator.query.api import ApiBackend
from secator.query.mongodb import MongoDBBackend
from secator.query.json import JsonBackend


__all__ = ['QueryEngine', 'QueryBackend', 'ApiBackend', 'MongoDBBackend', 'JsonBackend']


class QueryEngine:
    """Query engine with pluggable backends."""

    BACKENDS = {
        'api': ApiBackend,
        'mongodb': MongoDBBackend,
        'json': JsonBackend,
    }

    def __init__(self, workspace_id: str, context: dict = None):
        self.workspace_id = workspace_id
        self.context = context or {}
        self.backend = self._select_backend()

    def _select_backend(self) -> QueryBackend:
        """Select appropriate backend based on context."""
        if self.context.get('api', False):
            return ApiBackend(self.workspace_id)
        elif self.context.get('mongodb', False):
            return MongoDBBackend(self.workspace_id)
        else:
            return JsonBackend(self.workspace_id)

    def search(self, query: dict, limit: int = 100) -> List[Dict[str, Any]]:
        """Search for findings matching query."""
        return self.backend.search(query, limit)

    def count(self, query: dict) -> int:
        """Count findings matching query."""
        return self.backend.count(query)
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_query.py::TestQueryEngine -v`
Expected: PASS

**Step 5: Commit**

```bash
git add secator/query/__init__.py tests/unit/test_query.py
git commit -m "feat(query): add QueryEngine with auto-backend selection"
```

---

## Task 7: Intent Analysis (Phase 1)

**Files:**
- Modify: `secator/tasks/ai.py`
- Test: `tests/unit/test_ai_intent.py`

**Step 1: Write the failing test**

```python
# tests/unit/test_ai_intent.py

import unittest
import json


class TestIntentAnalysis(unittest.TestCase):

    def test_parse_intent_response_valid(self):
        from secator.tasks.ai import parse_intent_response

        response = json.dumps({
            "mode": "summarize",
            "queries": [{"_type": "vulnerability"}],
            "reasoning": "User wants a summary"
        })

        result = parse_intent_response(response)

        self.assertEqual(result['mode'], 'summarize')
        self.assertEqual(len(result['queries']), 1)
        self.assertEqual(result['queries'][0]['_type'], 'vulnerability')

    def test_parse_intent_response_with_code_block(self):
        from secator.tasks.ai import parse_intent_response

        response = '''Here's the analysis:
```json
{
    "mode": "attack",
    "queries": [{"_type": "url", "url": {"$contains": "login"}}],
    "reasoning": "User wants to attack login"
}
```
'''

        result = parse_intent_response(response)

        self.assertEqual(result['mode'], 'attack')
        self.assertEqual(result['queries'][0]['_type'], 'url')

    def test_parse_intent_response_invalid(self):
        from secator.tasks.ai import parse_intent_response

        response = "This is not valid JSON"

        result = parse_intent_response(response)

        self.assertIsNone(result)

    def test_get_output_types_schema(self):
        from secator.tasks.ai import get_output_types_schema

        schema = get_output_types_schema()

        self.assertIn('vulnerability', schema)
        self.assertIn('url', schema)
        self.assertIn('port', schema)
        self.assertIn('subdomain', schema)
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_ai_intent.py -v`
Expected: FAIL with "ImportError: cannot import name 'parse_intent_response'"

**Step 3: Write minimal implementation**

```python
# secator/tasks/ai.py - add these functions after the existing imports

import json
import re
from dataclasses import dataclass, fields
from typing import List, Dict, Any, Optional

# Add near top of file, after existing imports
from secator.output_types import FINDING_TYPES


def get_output_types_schema() -> str:
    """Generate schema description of output types for LLM."""
    schema_lines = []

    for output_type in FINDING_TYPES:
        type_name = output_type.get_name()
        type_fields = [f.name for f in fields(output_type) if not f.name.startswith('_') and f.name not in ['extra_data', 'tags', 'is_false_positive', 'is_acknowledged']]
        fields_str = ', '.join(type_fields[:10])  # Limit fields shown
        schema_lines.append(f"- {type_name}: {fields_str}")

    schema_lines.append("\nCommon fields (all types): _type, _source, _context, is_false_positive, tags, extra_data")

    return '\n'.join(schema_lines)


def parse_intent_response(response: str) -> Optional[Dict[str, Any]]:
    """Parse intent analysis response from LLM."""
    # Try direct JSON parse
    try:
        return json.loads(response)
    except json.JSONDecodeError:
        pass

    # Try to extract from code block
    json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', response, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group(1))
        except json.JSONDecodeError:
            pass

    # Try to find raw JSON object
    json_match = re.search(r'\{[^{}]*"mode"[^{}]*\}', response, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group())
        except json.JSONDecodeError:
            pass

    return None


INTENT_ANALYSIS_PROMPT = """You are a penetration testing assistant analyzing user requests.

Given the user's prompt and optional targets, determine:
1. Which mode to use (summarize, suggest, or attack)
2. What workspace queries to run to fetch relevant data

## Available Output Types

{output_types_schema}

## Query Operators

- Direct match: {{"field": "value"}}
- Regex: {{"field": {{"$regex": "pattern"}}}}
- Contains: {{"field": {{"$contains": "substring"}}}}
- Comparison: {{"field": {{"$gt|$gte|$lt|$lte": value}}}}
- In list: {{"field": {{"$in": ["a", "b"]}}}}
- Not equal: {{"field": {{"$ne": value}}}}
- Nested fields: {{"_context.workspace_name": "value"}}

## Response Format (JSON)

{{
    "mode": "summarize|suggest|attack",
    "queries": [
        {{"_type": "vulnerability", "severity": {{"$in": ["critical", "high"]}}}},
        {{"_type": "url", "url": {{"$contains": "login"}}}}
    ],
    "reasoning": "Brief explanation of why this mode and these queries"
}}

Respond with ONLY the JSON object, no additional text."""


def analyze_intent(
    prompt: str,
    targets: List[str],
    model: str = 'gpt-4o-mini',
    verbose: bool = False
) -> Optional[Dict[str, Any]]:
    """Phase 1: Analyze user intent and generate queries."""
    user_message = f"Prompt: {prompt}"
    if targets:
        user_message += f"\nTargets: {', '.join(targets)}"

    system_prompt = INTENT_ANALYSIS_PROMPT.format(
        output_types_schema=get_output_types_schema()
    )

    response = get_llm_response(
        prompt=user_message,
        model=model,
        system_prompt=system_prompt,
        temperature=0.3,
        verbose=verbose
    )

    if not response:
        return None

    return parse_intent_response(response)
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_ai_intent.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add secator/tasks/ai.py tests/unit/test_ai_intent.py
git commit -m "feat(ai): add intent analysis for Phase 1 LLM"
```

---

## Task 8: Safety Flags Handler

**Files:**
- Modify: `secator/tasks/ai.py`
- Test: `tests/unit/test_ai_safety.py`

**Step 1: Write the failing test**

```python
# tests/unit/test_ai_safety.py

import unittest
from unittest import mock


class TestSafetyFlags(unittest.TestCase):

    def test_add_rate_limit_nuclei(self):
        from secator.tasks.ai import add_rate_limit

        cmd = "secator x nuclei target.com"
        result = add_rate_limit(cmd, 10)

        self.assertIn('-rl 10', result)

    def test_add_rate_limit_nmap(self):
        from secator.tasks.ai import add_rate_limit

        cmd = "secator x nmap target.com"
        result = add_rate_limit(cmd, 100)

        self.assertIn('--max-rate 100', result)

    def test_add_rate_limit_already_present(self):
        from secator.tasks.ai import add_rate_limit

        cmd = "secator x nuclei target.com -rl 5"
        result = add_rate_limit(cmd, 10)

        # Should not add duplicate
        self.assertEqual(result.count('-rl'), 1)

    def test_add_rate_limit_unknown_tool(self):
        from secator.tasks.ai import add_rate_limit

        cmd = "secator x unknown_tool target.com"
        result = add_rate_limit(cmd, 10)

        # Should return unchanged
        self.assertEqual(cmd, result)


class TestSafetyCheck(unittest.TestCase):

    @mock.patch('secator.tasks.ai._is_ci', return_value=True)
    def test_check_action_safety_ci_auto_approve(self, mock_ci):
        from secator.tasks.ai import check_action_safety

        action = {
            'command': 'secator x sqlmap target.com',
            'destructive': True,
            'aggressive': True
        }

        should_run, cmd = check_action_safety(action, auto_yes=False, in_ci=True)

        self.assertTrue(should_run)
        self.assertEqual(cmd, action['command'])

    def test_check_action_safety_auto_yes(self):
        from secator.tasks.ai import check_action_safety

        action = {
            'command': 'secator x sqlmap target.com',
            'destructive': True,
            'aggressive': False
        }

        should_run, cmd = check_action_safety(action, auto_yes=True, in_ci=False)

        self.assertTrue(should_run)

    def test_check_action_safety_non_destructive(self):
        from secator.tasks.ai import check_action_safety

        action = {
            'command': 'secator x httpx target.com',
            'destructive': False,
            'aggressive': False
        }

        should_run, cmd = check_action_safety(action, auto_yes=False, in_ci=False)

        self.assertTrue(should_run)
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_ai_safety.py -v`
Expected: FAIL with "ImportError: cannot import name 'add_rate_limit'"

**Step 3: Write minimal implementation**

```python
# secator/tasks/ai.py - add these functions

TOOL_RATE_FLAGS = {
    'nuclei': '-rl {rate}',
    'httpx': '-rl {rate}',
    'nmap': '--max-rate {rate}',
    'ffuf': '-rate {rate}',
    'feroxbuster': '--rate-limit {rate}',
    'gobuster': '--delay {delay}ms',
    'dirsearch': '--delay {delay}',
    'sqlmap': '--delay {delay}',
}


def add_rate_limit(command: str, rate: int) -> str:
    """Add rate limit to command based on tool."""
    for tool, flag_template in TOOL_RATE_FLAGS.items():
        if f'secator x {tool}' in command or f' {tool} ' in command:
            # Check if rate flag already present
            flag_prefix = flag_template.split()[0]
            if flag_prefix in command:
                return command

            # Calculate delay for tools that use delay instead of rate
            delay = max(1, int(1000 / rate)) if 'delay' in flag_template else rate
            flag = flag_template.format(rate=rate, delay=delay)

            return f"{command} {flag}"

    return command


def check_action_safety(
    action: dict,
    auto_yes: bool,
    in_ci: bool
) -> tuple:
    """Check if action is safe to run, prompt if needed.

    Returns:
        tuple: (should_run: bool, modified_command: str)
    """
    destructive = action.get('destructive', False)
    aggressive = action.get('aggressive', False)
    command = action.get('command', '')

    # Auto-approve if --yes flag or CI environment
    if auto_yes or in_ci:
        return True, command

    # Non-destructive, non-aggressive: auto-approve
    if not destructive and not aggressive:
        return True, command

    # Handle destructive actions
    if destructive:
        from secator.rich import console
        console.print(f"[bold red]⚠ Destructive action:[/] {command}")
        console.print(f"[dim]Reasoning: {action.get('reasoning', 'N/A')}[/]")

        if not confirm_with_timeout("Execute this destructive action?", default=False):
            return False, command

    # Handle aggressive actions
    if aggressive:
        from secator.rich import console
        console.print(f"[bold orange1]⚠ Aggressive action (may trigger detection):[/] {command}")

        choice = _prompt_aggressive_action()

        if choice == 'skip':
            return False, command
        elif choice == 'limit':
            import click
            rate_limit = click.prompt("Rate limit (requests/sec)", type=int, default=10)
            command = add_rate_limit(command, rate_limit)
            return True, command
        # else: 'run' - continue as-is

    return True, command


def _prompt_aggressive_action() -> str:
    """Prompt user for aggressive action handling."""
    import click
    from secator.rich import console

    console.print("[R]un as-is / [S]kip / [L]imit rate: ", end='')

    while True:
        choice = click.getchar().lower()
        if choice == 'r':
            console.print('Run')
            return 'run'
        elif choice == 's':
            console.print('Skip')
            return 'skip'
        elif choice == 'l':
            console.print('Limit')
            return 'limit'
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_ai_safety.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add secator/tasks/ai.py tests/unit/test_ai_safety.py
git commit -m "feat(ai): add safety flags handler for destructive/aggressive actions"
```

---

## Task 9: AI Task Integration

**Files:**
- Modify: `secator/tasks/ai.py`
- Test: Manual testing

**Step 1: Update opts and yielder**

```python
# secator/tasks/ai.py - update the opts dict in the ai class

opts = {
    'prompt': {
        'type': str,
        'short': 'p',
        'default': '',
        'help': 'Natural language prompt for AI analysis',
    },
    'mode': {
        'type': str,
        'default': '',
        'help': 'Force operation mode: summarize, suggest, or attack (auto-detected if not set)',
    },
    'model': {
        'type': str,
        'default': 'gpt-4o-mini',
        'help': 'LLM model to use (via LiteLLM)',
    },
    'intent_model': {
        'type': str,
        'default': 'gpt-4o-mini',
        'help': 'LLM model for intent analysis (Phase 1)',
    },
    'encrypt_pii': {
        'is_flag': True,
        'default': True,
        'help': 'Encrypt PII data before sending to LLM',
    },
    'max_iterations': {
        'type': int,
        'default': 10,
        'help': 'Maximum attack loop iterations (attack mode only)',
    },
    'temperature': {
        'type': float,
        'default': 0.7,
        'help': 'LLM temperature for response generation',
    },
    'dry_run': {
        'is_flag': True,
        'default': False,
        'help': 'Show planned actions without executing (attack mode)',
    },
    'run': {
        'is_flag': True,
        'default': False,
        'help': 'Execute suggested tasks (suggest mode only)',
    },
    'yes': {
        'is_flag': True,
        'default': False,
        'short': 'y',
        'help': 'Auto-accept prompts without confirmation',
    },
    'verbose': {
        'is_flag': True,
        'default': False,
        'short': 'v',
        'help': 'Show verbose LLM debug output',
    },
}
```

**Step 2: Update yielder method**

```python
# secator/tasks/ai.py - replace the yielder method

def yielder(self) -> Generator:
    """Execute AI task based on selected mode."""
    try:
        import litellm  # noqa: F401
    except ImportError:
        yield Error(message="litellm is required. Install with: pip install litellm")
        return

    prompt = self.run_opts.get('prompt', '')
    mode_override = self.run_opts.get('mode', '')
    model = self.run_opts.get('model', 'gpt-4o-mini')
    intent_model = self.run_opts.get('intent_model', 'gpt-4o-mini')
    encrypt_pii = self.run_opts.get('encrypt_pii', True)
    verbose = self.run_opts.get('verbose', False)

    workspace_id = self.context.get('workspace_id')
    targets = self.inputs

    # Validate inputs
    if not prompt and not targets:
        yield Warning(message="No prompt or targets provided. Use --prompt or provide targets.")
        return

    # Initialize PII encryptor
    pii_encryptor = PIIEncryptor()

    # Phase 1: Intent Analysis (if prompt provided and mode not forced)
    if prompt and not mode_override:
        yield Info(message="Analyzing intent...")

        intent = analyze_intent(
            prompt=prompt,
            targets=targets,
            model=intent_model,
            verbose=verbose
        )

        if intent:
            mode = intent.get('mode', 'summarize')
            queries = intent.get('queries', [])
            yield Info(message=f"Mode: {mode}, Queries: {len(queries)}")
        else:
            yield Warning(message="Could not analyze intent, defaulting to summarize mode")
            mode = 'summarize'
            queries = [{}]
    else:
        mode = mode_override or 'summarize'
        queries = [{}]

    # Fetch workspace results if workspace_id available
    results = []
    if workspace_id:
        from secator.query import QueryEngine

        yield Info(message=f"Fetching results from workspace {workspace_id}...")
        engine = QueryEngine(workspace_id, context=self.context)

        for query in queries:
            query_results = engine.search(query, limit=100)
            results.extend(query_results)

        # Deduplicate by _uuid
        seen_uuids = set()
        unique_results = []
        for r in results:
            uuid = r.get('_uuid', id(r))
            if uuid not in seen_uuids:
                seen_uuids.add(uuid)
                unique_results.append(r)
        results = unique_results

        yield Info(message=f"Fetched {len(results)} results from workspace")
    else:
        results = self._previous_results or self.results

    # Format context for LLM
    context_text = ""
    if results:
        context_text = format_results_for_llm(results)
        if encrypt_pii:
            context_text = pii_encryptor.encrypt_pii(context_text)
            yield Info(message=f"PII encrypted: {len(pii_encryptor.pii_map)} sensitive values masked")

    if targets:
        targets_text = f"\n\n## Targets\n{', '.join(targets)}"
        if encrypt_pii:
            targets_text = pii_encryptor.encrypt_pii(targets_text)
        context_text += targets_text

    if prompt:
        context_text = f"## User Request\n{prompt}\n\n{context_text}"

    yield Info(message=f"Starting AI analysis in '{mode}' mode using {model}")

    # Phase 2: Execute mode
    if mode == 'summarize':
        yield from self._mode_summarize(context_text, model, pii_encryptor, results, targets)
    elif mode == 'suggest':
        yield from self._mode_suggest(context_text, model, pii_encryptor, results, targets)
    elif mode == 'attack':
        yield from self._mode_attack(context_text, model, pii_encryptor, results, targets)
    else:
        yield Error(message=f"Unknown mode: {mode}. Use: summarize, suggest, or attack")
```

**Step 3: Update attack mode to use safety checks**

```python
# secator/tasks/ai.py - in _mode_attack method, update the execute action handler

elif action_type == 'execute':
    command = action.get('command', '')
    target = action.get('target', '')

    # Scope check
    if not self._is_in_scope(target, targets):
        yield Warning(message=f"Target {target} is out of scope, skipping")
        prompt = f"Target {target} was out of scope. Only test: {', '.join(targets)}. Choose another action.\n\nContext:\n{json.dumps(attack_context)}"
        continue

    # Safety check
    should_run, modified_command = check_action_safety(
        action,
        auto_yes=self.run_opts.get('yes', False),
        in_ci=_is_ci()
    )

    if not should_run:
        yield Info(message=f"Skipped: {command}")
        attack_context['skipped_actions'] = attack_context.get('skipped_actions', [])
        attack_context['skipped_actions'].append(command)
        prompt = f"Action was skipped by user. Choose another approach.\n\nContext:\n{json.dumps(attack_context)}"
        continue

    yield Info(message=f"Executing: {modified_command}")

    if dry_run:
        yield Tag(
            name='dry_run_command',
            value=modified_command,
            match=target,
            category='attack',
            extra_data={'reasoning': action.get('reasoning', '')}
        )
        result_output = "[DRY RUN] Command not executed"
    else:
        result_output = self._execute_command(modified_command)

    # ... rest of execute handling
```

**Step 4: Update attack mode system prompt**

```python
# secator/tasks/ai.py - update SYSTEM_PROMPTS['attack']

'attack': """You are an autonomous penetration testing agent conducting authorized security testing.

Your mission is to:
1. Analyze the current findings and identify exploitable vulnerabilities
2. Plan attack sequences to validate vulnerabilities
3. Execute attacks using available tools (curl, secator tasks, etc.)
4. Validate successful exploits with proof-of-concept
5. Document findings with reproduction steps

IMPORTANT RULES:
- Only test targets explicitly provided as inputs
- Document every action taken
- Stop if you encounter out-of-scope systems
- Provide clear proof for each validated vulnerability

For each attack attempt, respond with JSON:
{
    "action": "execute|validate|report|complete",
    "tool": "tool_name",
    "command": "full command to run",
    "target": "specific target",
    "destructive": true|false,
    "aggressive": true|false,
    "reasoning": "why this attack",
    "expected_outcome": "what we expect to find"
}

## destructive: true when:
- POST/PUT/DELETE/PATCH requests
- SQL injection exploitation (sqlmap --dump, etc.)
- XSS payload injection
- RCE exploitation attempts
- File upload/write operations
- Authentication bypass attempts
- Any action that modifies target state

## aggressive: true when:
- No rate limit specified (-rate, --rate-limit, -rl)
- High thread/concurrency (threads > 50, -c > 50)
- Large wordlists without throttling
- Brute force without delays
- Full port scans without rate limiting
- Actions likely to trigger IDS/WAF

When validating a vulnerability, include:
{
    "action": "validate",
    "vulnerability": "name",
    "target": "target url or host",
    "proof": "evidence of exploitation",
    "severity": "critical|high|medium|low|info",
    "reproduction_steps": ["step1", "step2", ...]
}

When done, respond with:
{"action": "complete", "summary": "overall findings"}""",
```

**Step 5: Manual testing**

Run: `secator x ai -p "What vulnerabilities have we found?" -ws <workspace_id>`

Run: `secator x ai -p "Suggest next scans for target.com" target.com`

Run: `secator x ai -p "Test for SQL injection" target.com --mode attack --dry-run`

**Step 6: Commit**

```bash
git add secator/tasks/ai.py
git commit -m "feat(ai): integrate two-phase LLM with query engine and safety flags"
```

---

## Final Integration Test

**Step 1: Run all unit tests**

```bash
python -m pytest tests/unit/test_query.py tests/unit/test_ai_intent.py tests/unit/test_ai_safety.py tests/unit/test_config.py::TestAIConfig -v
```

**Step 2: Run linting**

```bash
secator test lint
```

**Step 3: Final commit if needed**

```bash
git add -A
git commit -m "test: add comprehensive tests for AI workspace query feature"
```

---

## Summary

| Task | Description | Files |
|------|-------------|-------|
| 1 | Configuration changes | `config.py`, `test_config.py` |
| 2 | Query backend base class | `query/_base.py`, `test_query.py` |
| 3 | JSON query backend | `query/json.py`, `test_query.py` |
| 4 | MongoDB query backend | `query/mongodb.py`, `test_query.py` |
| 5 | API query backend | `query/api.py`, `test_query.py` |
| 6 | Query engine | `query/__init__.py`, `test_query.py` |
| 7 | Intent analysis | `tasks/ai.py`, `test_ai_intent.py` |
| 8 | Safety flags handler | `tasks/ai.py`, `test_ai_safety.py` |
| 9 | AI task integration | `tasks/ai.py` |
