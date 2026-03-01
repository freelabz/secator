# AI Task Workspace Query Support

**Date:** 2026-02-20
**Status:** Approved
**Author:** Claude + User

## Overview

Enhance the AI task to support running with no targets by fetching workspace results automatically. Users can query their workspace using natural language prompts, and the AI intelligently selects the appropriate mode and constructs queries to fetch relevant data.

## Goals

1. Allow `secator x ai --prompt "..." -ws <id>` without requiring targets
2. Implement two-phase LLM architecture (intent analysis + execution)
3. Create pluggable query backend system (API, MongoDB, JSON)
4. Add safety flags (`destructive`, `aggressive`) for attack mode
5. Smart auto-filtering of workspace results based on prompt

## Non-Goals

- Modifying the existing mode behaviors (summarize, suggest, attack)
- Adding new output types
- Changing the API endpoint schemas

## CLI Interface

### New/Modified Options

```python
opts = {
    'prompt': {
        'type': str,
        'short': 'p',
        'default': '',
        'help': 'Natural language prompt for AI analysis',
    },
    'mode': {
        'type': str,
        'default': '',  # Now optional, auto-detected from prompt
        'help': 'Force operation mode: summarize, suggest, or attack',
    },
    'intent_model': {
        'type': str,
        'default': CONFIG.ai.intent_model,
        'help': 'LLM model for intent analysis (Phase 1)',
    },
}
```

### Usage Examples

```bash
# Prompt-only: analyze all workspace results
secator x ai -p "Summarize findings" -ws <id>

# Prompt + targets: AI decides how to use targets in queries
secator x ai -p "Run deep penetration tests on URLs" vulnweb.com -ws <id>
# -> AI constructs: {"_type": "url", "url": {"$contains": "vulnweb.com"}}

secator x ai -p "What ports are open on these hosts?" 192.168.1.0/24 -ws <id>
# -> AI constructs: {"_type": "port", "ip": {"$startswith": "192.168.1."}}

# Force specific mode
secator x ai -p "Focus on auth issues" --mode attack -ws <id>

# Legacy behavior still works
secator x ai example.com --mode summarize
```

## Architecture

### Two-Phase LLM Flow

```
User: secator x ai -p "Find critical vulns on login pages" target.com -ws abc123
                                    |
                                    v
                    +-------------------------------+
                    |  Phase 1: Intent Analysis     |
                    |  (fast model: gpt-4o-mini)    |
                    |                               |
                    |  -> mode: "summarize"         |
                    |  -> queries: [                |
                    |      {_type: vulnerability,   |
                    |       severity: critical},    |
                    |      {_type: url,             |
                    |       url: {$contains: login}}|
                    |    ]                          |
                    +---------------+---------------+
                                    |
                                    v
                    +-------------------------------+
                    |  QueryEngine                  |
                    |  (auto-selects backend)       |
                    |                               |
                    |  Priority: API > MongoDB > JSON|
                    |                               |
                    |  Base query ALWAYS enforced   |
                    +---------------+---------------+
                                    |
                                    v
                    +-------------------------------+
                    |  Phase 2: Execution           |
                    |  (configured model)           |
                    |                               |
                    |  Mode: summarize/suggest/     |
                    |        attack                 |
                    |                               |
                    |  Safety checks for attack     |
                    +-------------------------------+
```

### Phase 1: Intent Analysis

The AI analyzes the user's prompt and optional targets to determine:
1. Which mode to use (summarize, suggest, attack)
2. What queries to construct to fetch relevant workspace data

**Intent Analysis Prompt:**

```
You are a penetration testing assistant analyzing user requests.

Given the user's prompt and optional targets, determine:
1. Which mode to use (summarize, suggest, or attack)
2. What workspace queries to run to fetch relevant data

## Available Output Types

- subdomain: host, domain, verified, sources
- ip: ip, host, alive, protocol
- port: port, ip, state, service_name, cpes, host, protocol
- url: url, host, status_code, title, webserver, tech, content_type, method, is_root, is_directory
- vulnerability: name, severity (critical/high/medium/low/info), cvss_score, matched_at, confidence, provider, tags
- exploit: name, provider, id, matched_at, cves, reference
- tag: name, value, match, category
- user_account: username, email, url
- certificate: host, subject, issuer, expires
- record: host, type, value (DNS records)
- domain: name, registrar, created_at

Common fields (all types): _type, _source, _context, is_false_positive, tags, extra_data

## Query Operators

- Direct match: {"field": "value"}
- Regex: {"field": {"$regex": "pattern"}}
- Contains: {"field": {"$contains": "substring"}}
- Comparison: {"field": {"$gt|$gte|$lt|$lte": value}}
- In list: {"field": {"$in": ["a", "b"]}}
- Not equal: {"field": {"$ne": value}}
- Nested fields: {"_context.workspace_name": "value"}

## Response Format (JSON)

{
    "mode": "summarize|suggest|attack",
    "queries": [
        {"_type": "vulnerability", "severity": {"$in": ["critical", "high"]}},
        {"_type": "url", "url": {"$contains": "login"}}
    ],
    "reasoning": "Brief explanation of why this mode and these queries"
}
```

**Response Schema:**

```python
@dataclass
class IntentAnalysis:
    mode: str  # summarize, suggest, attack
    queries: List[dict]
    reasoning: str
```

### Phase 2: Execution

After fetching results via QueryEngine, execute the selected mode with full context. The existing mode implementations (summarize, suggest, attack) are used with the fetched results.

## Query Backend System

### Directory Structure

```
secator/query/
├── __init__.py      # QueryEngine + auto-detection
├── _base.py         # Abstract base class
├── api.py           # API backend
├── mongodb.py       # MongoDB backend
├── json.py          # Filesystem/JSON backend
```

### Base Interface

```python
# secator/query/_base.py
from abc import ABC, abstractmethod
from typing import List, Dict, Any

class QueryBackend(ABC):
    """Abstract base class for query backends."""

    name: str = "base"

    # Fields that cannot be overridden by user queries
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

        # Remove any attempts to override protected fields
        for field in self.PROTECTED_FIELDS:
            if field in merged:
                del merged[field]

        # Base query takes precedence
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

### Query Engine

```python
# secator/query/__init__.py
from secator.query.api import ApiBackend
from secator.query.mongodb import MongoDBBackend
from secator.query.json import JsonBackend

class QueryEngine:
    """Query engine with pluggable backends."""

    BACKENDS = {
        'api': ApiBackend,
        'mongodb': MongoDBBackend,
        'json': JsonBackend,
    }

    def __init__(self, workspace_id: str, context: dict = None):
        self.workspace_id = workspace_id
        self.backend = self._select_backend(context or {})

    def _select_backend(self, context: dict) -> QueryBackend:
        if context.get('api', False):
            return ApiBackend(self.workspace_id)
        elif context.get('mongodb', False):
            return MongoDBBackend(self.workspace_id)
        else:
            return JsonBackend(self.workspace_id)

    def search(self, query: dict, limit: int = 100) -> List[OutputType]:
        return self.backend.search(query, limit)

    def count(self, query: dict) -> int:
        return self.backend.count(query)
```

### Backend Implementations

**API Backend:**
- Uses `POST /api/findings/_search` endpoint
- Passes query as JSON body
- Adds `_tagged: true` to base query (API-specific)

**MongoDB Backend:**
- Direct MongoDB queries via pymongo
- Uses existing `get_mongodb_client()` from hooks
- Adds `_tagged: true` to base query

**JSON Backend:**
- Reads JSON files from `~/.secator/reports/<workspace_id>/`
- Converts MongoDB-style queries to Python filters
- Supported operators: `$regex`, `$contains`, `$startswith`, `$in`, `$gt`, `$gte`, `$lt`, `$lte`, `$ne`

### Query Conversion (JSON Backend)

```python
OPERATORS = {
    "$regex": lambda field, pattern: re.search(pattern, str(field)) is not None,
    "$contains": lambda field, value: value in str(field),
    "$startswith": lambda field, value: str(field).startswith(value),
    "$in": lambda field, values: field in values,
    "$gt": lambda field, value: field > value,
    "$gte": lambda field, value: field >= value,
    "$lt": lambda field, value: field < value,
    "$lte": lambda field, value: field <= value,
    "$ne": lambda field, value: field != value,
}

def match_query(item: dict, query: dict) -> bool:
    """Check if item matches MongoDB-style query."""
    for key, condition in query.items():
        value = get_nested_field(item, key)  # handles "a.b.c" paths
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
```

## Safety Flags

### Attack Mode Response Schema

```json
{
    "action": "execute|validate|report|complete",
    "command": "full command to run",
    "target": "specific target",
    "destructive": true,
    "aggressive": true,
    "reasoning": "why this action",
    "expected_outcome": "what we expect to find"
}
```

### Flag Definitions

**destructive: true** when:
- POST/PUT/DELETE/PATCH requests
- SQL injection exploitation (sqlmap --dump, etc.)
- XSS payload injection
- RCE exploitation attempts
- File upload/write operations
- Authentication bypass attempts
- Any action that modifies target state

**aggressive: true** when:
- No rate limit specified (-rate, --rate-limit, -rl)
- High thread/concurrency (threads > 50, -c > 50)
- Large wordlists without throttling
- Brute force without delays
- Full port scans without rate limiting
- Actions likely to trigger IDS/WAF

### Safety Handler Behavior

| Condition | Behavior |
|-----------|----------|
| `destructive: true` + not CI + not `--yes` | Prompt: "Execute destructive action?" |
| `aggressive: true` + not CI + not `--yes` | Prompt: "[R]un / [S]kip / [L]imit rate" |
| `--yes` flag or CI | Auto-approve all |
| `--dry-run` | Show planned action, don't execute |

### Rate Limit Injection

When user chooses to limit rate, the handler injects appropriate flags:

```python
tool_rate_flags = {
    'nuclei': '-rl {rate}',
    'httpx': '-rl {rate}',
    'nmap': '--max-rate {rate}',
    'ffuf': '-rate {rate}',
    'feroxbuster': '--rate-limit {rate}',
    'sqlmap': '--delay {delay}',  # 1/rate
}
```

## Configuration Changes

### secator/config.py

```python
class ApiAddon(StrictModel):
    # ... existing fields ...
    finding_search_endpoint: str = 'findings/_search'  # NEW


class AI(StrictModel):
    """AI task configuration."""
    default_model: str = 'gpt-4o-mini'
    intent_model: str = 'gpt-4o-mini'  # Model for Phase 1 (fast/cheap)
    execution_model: str = 'gpt-4o-mini'  # Model for Phase 2
    temperature: float = 0.7
    max_tokens: int = 4096
    max_results: int = 500  # Max results to fetch from workspace
    encrypt_pii: bool = True


class SecatorConfig(StrictModel):
    # ... existing ...
    ai: AI = AI()  # NEW
```

### Environment Variables

```bash
SECATOR_AI_DEFAULT_MODEL=claude-3-opus
SECATOR_AI_INTENT_MODEL=gpt-4o-mini
SECATOR_AI_EXECUTION_MODEL=gpt-4o
SECATOR_AI_MAX_RESULTS=1000
SECATOR_ADDONS_API_FINDING_SEARCH_ENDPOINT=findings/_search
```

## Security Considerations

### Workspace Scoping

The base query is **always enforced** and protected fields cannot be overridden:

```python
PROTECTED_FIELDS = [
    "_context.workspace_id",
    "_context.workspace_duplicate",
]

# AI generates:
query = {"_context.workspace_id": "malicious_id", "_type": "vulnerability"}

# After _merge_query():
safe_query = {
    "_type": "vulnerability",
    "_context.workspace_id": "actual_workspace_id",  # Enforced
    "_context.workspace_duplicate": False,            # Enforced
    "is_false_positive": False                        # Enforced
}
```

### Command Execution

- Existing allowlist for commands remains in place
- Scope check validates targets before execution
- `destructive` and `aggressive` flags add user confirmation layer

## Files to Modify/Create

| File | Action | Description |
|------|--------|-------------|
| `secator/tasks/ai.py` | Modify | Add `--prompt`, two-phase LLM, safety flags |
| `secator/query/__init__.py` | Create | QueryEngine class |
| `secator/query/_base.py` | Create | Abstract QueryBackend |
| `secator/query/api.py` | Create | API backend implementation |
| `secator/query/mongodb.py` | Create | MongoDB backend implementation |
| `secator/query/json.py` | Create | JSON/filesystem backend |
| `secator/config.py` | Modify | Add `finding_search_endpoint`, `AI` config |

## Testing Strategy

1. **Unit Tests:**
   - Query backend implementations
   - Query merging and protected field enforcement
   - MongoDB-to-JSON query conversion
   - Safety flag detection

2. **Integration Tests:**
   - End-to-end prompt -> query -> results flow
   - Each backend with real data
   - Safety prompts in attack mode

3. **Manual Testing:**
   - Various natural language prompts
   - Edge cases (no results, malformed queries)
   - Rate limiting injection
