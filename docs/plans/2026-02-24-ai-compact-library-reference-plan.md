# AI Compact Library Reference Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add compact pipe-delimited library reference to AI prompts with task descriptions, options, workflows, profiles, wordlists, and output types.

**Architecture:** Add builder functions to `ai_prompts.py` that dynamically generate compact references from secator's loaders and config. Update `SYSTEM_ATTACK` prompt to include the combined library reference.

**Tech Stack:** Python, secator loaders (`discover_tasks`, `get_configs_by_type`), secator config (`CONFIG.wordlists`)

---

### Task 1: Add build_tasks_reference function

**Files:**
- Modify: `secator/tasks/ai_prompts.py:42-46`
- Test: `tests/unit/test_ai_prompts.py`

**Step 1: Write the failing test**

Add to `tests/unit/test_ai_prompts.py`:

```python
def test_build_tasks_reference_format(self):
    from secator.tasks.ai_prompts import build_tasks_reference
    result = build_tasks_reference()
    # Should be pipe-delimited format
    lines = result.strip().split('\n')
    self.assertTrue(len(lines) > 0)
    # Each line should have name|description|options format
    first_line = lines[0]
    parts = first_line.split('|')
    self.assertEqual(len(parts), 3, f"Expected 3 parts (name|desc|opts), got: {first_line}")

def test_build_tasks_reference_excludes_ai(self):
    from secator.tasks.ai_prompts import build_tasks_reference
    result = build_tasks_reference()
    # Should not include the Ai task itself
    self.assertNotIn('Ai|', result)
    self.assertNotIn('ai|', result)
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_ai_prompts.py::TestPrompts::test_build_tasks_reference_format -v`
Expected: FAIL with "cannot import name 'build_tasks_reference'"

**Step 3: Write minimal implementation**

Add to `secator/tasks/ai_prompts.py` after line 46:

```python
def build_tasks_reference() -> str:
    """Build compact task reference: name|description|options."""
    from secator.loader import discover_tasks
    from secator.definitions import OPT_NOT_SUPPORTED

    lines = []
    for task_cls in sorted(discover_tasks(), key=lambda t: t.__name__):
        if task_cls.__name__ == "Ai":
            continue
        name = task_cls.__name__
        desc = (task_cls.__doc__ or "").strip().split('\n')[0][:50]

        # Get task-specific options
        task_opts = list(getattr(task_cls, 'opts', {}).keys())

        # Get generic options that this task supports
        opt_key_map = getattr(task_cls, 'opt_key_map', {})
        generic_opts = [k for k, v in opt_key_map.items() if v != OPT_NOT_SUPPORTED]

        all_opts = ",".join(sorted(set(task_opts + generic_opts)))
        lines.append(f"{name}|{desc}|{all_opts}")

    return "\n".join(lines)
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_ai_prompts.py::TestPrompts::test_build_tasks_reference_format tests/unit/test_ai_prompts.py::TestPrompts::test_build_tasks_reference_excludes_ai -v`
Expected: PASS

**Step 5: Commit**

```bash
git add secator/tasks/ai_prompts.py tests/unit/test_ai_prompts.py
git commit -m "feat(ai): add build_tasks_reference function"
```

---

### Task 2: Add build_workflows_reference function

**Files:**
- Modify: `secator/tasks/ai_prompts.py`
- Test: `tests/unit/test_ai_prompts.py`

**Step 1: Write the failing test**

Add to `tests/unit/test_ai_prompts.py`:

```python
def test_build_workflows_reference_format(self):
    from secator.tasks.ai_prompts import build_workflows_reference
    result = build_workflows_reference()
    # Should have workflow entries (may be empty if no workflows configured)
    if result:
        lines = result.strip().split('\n')
        first_line = lines[0]
        parts = first_line.split('|')
        self.assertGreaterEqual(len(parts), 1, "Should have at least workflow name")
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_ai_prompts.py::TestPrompts::test_build_workflows_reference_format -v`
Expected: FAIL with "cannot import name 'build_workflows_reference'"

**Step 3: Write minimal implementation**

Add to `secator/tasks/ai_prompts.py`:

```python
def build_workflows_reference() -> str:
    """Build compact workflow reference: name|description."""
    from secator.loader import get_configs_by_type
    workflows = get_configs_by_type('workflow')
    lines = []
    for w in sorted(workflows, key=lambda x: x.name):
        desc = getattr(w, 'description', '') or ''
        lines.append(f"{w.name}|{desc}")
    return "\n".join(lines)
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_ai_prompts.py::TestPrompts::test_build_workflows_reference_format -v`
Expected: PASS

**Step 5: Commit**

```bash
git add secator/tasks/ai_prompts.py tests/unit/test_ai_prompts.py
git commit -m "feat(ai): add build_workflows_reference function"
```

---

### Task 3: Add build_profiles_reference function

**Files:**
- Modify: `secator/tasks/ai_prompts.py`
- Test: `tests/unit/test_ai_prompts.py`

**Step 1: Write the failing test**

Add to `tests/unit/test_ai_prompts.py`:

```python
def test_build_profiles_reference_format(self):
    from secator.tasks.ai_prompts import build_profiles_reference
    result = build_profiles_reference()
    # Should have profile entries (may be empty if no profiles configured)
    if result:
        lines = result.strip().split('\n')
        first_line = lines[0]
        parts = first_line.split('|')
        self.assertGreaterEqual(len(parts), 1, "Should have at least profile name")
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_ai_prompts.py::TestPrompts::test_build_profiles_reference_format -v`
Expected: FAIL with "cannot import name 'build_profiles_reference'"

**Step 3: Write minimal implementation**

Add to `secator/tasks/ai_prompts.py`:

```python
def build_profiles_reference() -> str:
    """Build compact profiles reference: name|description."""
    from secator.loader import get_configs_by_type
    profiles = get_configs_by_type('profile')
    lines = []
    for p in sorted(profiles, key=lambda x: x.name):
        desc = getattr(p, 'description', '') or ''
        lines.append(f"{p.name}|{desc}")
    return "\n".join(lines)
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_ai_prompts.py::TestPrompts::test_build_profiles_reference_format -v`
Expected: PASS

**Step 5: Commit**

```bash
git add secator/tasks/ai_prompts.py tests/unit/test_ai_prompts.py
git commit -m "feat(ai): add build_profiles_reference function"
```

---

### Task 4: Add build_wordlists_reference function

**Files:**
- Modify: `secator/tasks/ai_prompts.py`
- Test: `tests/unit/test_ai_prompts.py`

**Step 1: Write the failing test**

Add to `tests/unit/test_ai_prompts.py`:

```python
def test_build_wordlists_reference_format(self):
    from secator.tasks.ai_prompts import build_wordlists_reference
    result = build_wordlists_reference()
    # Should return string (may be empty if no wordlists configured)
    self.assertIsInstance(result, str)
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_ai_prompts.py::TestPrompts::test_build_wordlists_reference_format -v`
Expected: FAIL with "cannot import name 'build_wordlists_reference'"

**Step 3: Write minimal implementation**

Add to `secator/tasks/ai_prompts.py`:

```python
def build_wordlists_reference() -> str:
    """Build compact wordlists reference from CONFIG."""
    from secator.config import CONFIG
    lines = []
    if CONFIG.wordlists.templates:
        for name in sorted(CONFIG.wordlists.templates.keys()):
            lines.append(name)
    return "\n".join(lines)
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_ai_prompts.py::TestPrompts::test_build_wordlists_reference_format -v`
Expected: PASS

**Step 5: Commit**

```bash
git add secator/tasks/ai_prompts.py tests/unit/test_ai_prompts.py
git commit -m "feat(ai): add build_wordlists_reference function"
```

---

### Task 5: Add build_output_types_reference function

**Files:**
- Modify: `secator/tasks/ai_prompts.py`
- Test: `tests/unit/test_ai_prompts.py`

**Step 1: Write the failing test**

Add to `tests/unit/test_ai_prompts.py`:

```python
def test_build_output_types_reference_format(self):
    from secator.tasks.ai_prompts import build_output_types_reference
    result = build_output_types_reference()
    # Should have output type entries
    lines = result.strip().split('\n')
    self.assertTrue(len(lines) > 0)
    # Each line should have name|fields format
    first_line = lines[0]
    parts = first_line.split('|')
    self.assertEqual(len(parts), 2, f"Expected 2 parts (name|fields), got: {first_line}")

def test_build_output_types_reference_has_vulnerability(self):
    from secator.tasks.ai_prompts import build_output_types_reference
    result = build_output_types_reference()
    self.assertIn('vulnerability|', result)
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_ai_prompts.py::TestPrompts::test_build_output_types_reference_format -v`
Expected: FAIL with "cannot import name 'build_output_types_reference'"

**Step 3: Write minimal implementation**

Add to `secator/tasks/ai_prompts.py`:

```python
def build_output_types_reference() -> str:
    """Build compact output types reference: name|queryable_fields."""
    from secator.output_types import FINDING_TYPES
    lines = []
    for cls in FINDING_TYPES:
        name = cls.get_name()
        # Get dataclass fields, excluding private ones
        if hasattr(cls, '__dataclass_fields__'):
            fields = ",".join(
                f.name for f in cls.__dataclass_fields__.values()
                if not f.name.startswith('_')
            )
        else:
            fields = ""
        lines.append(f"{name}|{fields}")
    return "\n".join(lines)
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_ai_prompts.py::TestPrompts::test_build_output_types_reference_format tests/unit/test_ai_prompts.py::TestPrompts::test_build_output_types_reference_has_vulnerability -v`
Expected: PASS

**Step 5: Commit**

```bash
git add secator/tasks/ai_prompts.py tests/unit/test_ai_prompts.py
git commit -m "feat(ai): add build_output_types_reference function"
```

---

### Task 6: Add OPTION_FORMATS constant and build_library_reference function

**Files:**
- Modify: `secator/tasks/ai_prompts.py`
- Test: `tests/unit/test_ai_prompts.py`

**Step 1: Write the failing test**

Add to `tests/unit/test_ai_prompts.py`:

```python
def test_option_formats_has_header(self):
    from secator.tasks.ai_prompts import OPTION_FORMATS
    self.assertIn('header|', OPTION_FORMATS)
    self.assertIn(';;', OPTION_FORMATS)  # Header format hint

def test_build_library_reference_has_all_sections(self):
    from secator.tasks.ai_prompts import build_library_reference
    result = build_library_reference()
    self.assertIn('TASKS:', result)
    self.assertIn('WORKFLOWS:', result)
    self.assertIn('PROFILES:', result)
    self.assertIn('WORDLISTS:', result)
    self.assertIn('OUTPUT_TYPES:', result)
    self.assertIn('OPTION_FORMATS:', result)
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_ai_prompts.py::TestPrompts::test_option_formats_has_header -v`
Expected: FAIL with "cannot import name 'OPTION_FORMATS'"

**Step 3: Write minimal implementation**

Add to `secator/tasks/ai_prompts.py` (after imports, before SYSTEM_ATTACK):

```python
OPTION_FORMATS = """header|key1:value1;;key2:value2|Multiple headers separated by ;;
cookie|name1=val1;name2=val2|Standard cookie format
proxy|http://host:port|HTTP/SOCKS proxy URL
wordlist|name_or_path|Use predefined name or file path
ports|1-1000,8080,8443|Comma-separated ports or ranges"""
```

Add function:

```python
def build_library_reference() -> str:
    """Build complete library reference in compact format."""
    sections = [
        "TASKS:\n" + build_tasks_reference(),
        "WORKFLOWS:\n" + build_workflows_reference(),
        "PROFILES:\n" + build_profiles_reference(),
        "WORDLISTS:\n" + build_wordlists_reference(),
        "OUTPUT_TYPES:\n" + build_output_types_reference(),
        "OPTION_FORMATS:\n" + OPTION_FORMATS,
    ]
    return "\n\n".join(sections)
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_ai_prompts.py::TestPrompts::test_option_formats_has_header tests/unit/test_ai_prompts.py::TestPrompts::test_build_library_reference_has_all_sections -v`
Expected: PASS

**Step 5: Commit**

```bash
git add secator/tasks/ai_prompts.py tests/unit/test_ai_prompts.py
git commit -m "feat(ai): add OPTION_FORMATS and build_library_reference"
```

---

### Task 7: Update SYSTEM_ATTACK prompt and get_system_prompt function

**Files:**
- Modify: `secator/tasks/ai_prompts.py:6-28` (SYSTEM_ATTACK)
- Modify: `secator/tasks/ai_prompts.py:56-73` (get_system_prompt)
- Test: `tests/unit/test_ai_prompts.py`

**Step 1: Write the failing test**

Update existing test in `tests/unit/test_ai_prompts.py`:

```python
def test_get_system_prompt_attack_has_library_reference(self):
    prompt = get_system_prompt("attack")
    # Should have all library reference sections
    self.assertIn('TASKS:', prompt)
    self.assertIn('WORKFLOWS:', prompt)
    self.assertIn('PROFILES:', prompt)
    self.assertIn('OUTPUT_TYPES:', prompt)
    self.assertIn('OPTION_FORMATS:', prompt)
    # Should have query operators
    self.assertIn('$in', prompt)
    self.assertIn('$regex', prompt)
    # Should have profiles usage hint
    self.assertIn('profiles', prompt)
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/test_ai_prompts.py::TestPrompts::test_get_system_prompt_attack_has_library_reference -v`
Expected: FAIL with "AssertionError: 'PROFILES:' not found"

**Step 3: Write minimal implementation**

Replace `SYSTEM_ATTACK` in `secator/tasks/ai_prompts.py`:

```python
SYSTEM_ATTACK = """Security testing assistant. Execute actions against provided targets.

RESPONSE FORMAT:
1. Brief reasoning (2-3 sentences max)
2. JSON array of actions

ACTIONS:
- task: {{"action":"task","name":"<tool>","targets":[...],"opts":{{}}}}
- workflow: {{"action":"workflow","name":"<name>","targets":[...],"opts":{{"profiles":["aggressive"]}}}}
- shell: {{"action":"shell","command":"<cmd>"}}
- query: {{"action":"query","type":"<output_type>","filter":{{}}}}
- done: {{"action":"done","reason":"<why>"}}

RULES:
- One action array per response
- Never invent tool output
- Use workspace queries to get historical data for context
- Targets are encrypted as [HOST:xxxx] - use as-is
- Only use options listed below for each task
- To use profiles, add "profiles": ["name"] in opts

{library_reference}

QUERY OPERATORS: $in, $regex, $contains, $gt, $lt, $ne
Example: {{"action":"query","type":"vulnerability","filter":{{"severity":{{"$in":["critical","high"]}}}}}}
"""
```

Update `get_system_prompt` function:

```python
def get_system_prompt(mode: str) -> str:
    """Get system prompt for mode with library reference filled in.

    Args:
        mode: Either "attack" or "chat"

    Returns:
        Formatted system prompt string
    """
    if mode == "attack":
        return SYSTEM_ATTACK.format(
            library_reference=build_library_reference()
        )
    elif mode == "chat":
        return SYSTEM_CHAT
    else:
        return SYSTEM_CHAT
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/test_ai_prompts.py -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add secator/tasks/ai_prompts.py tests/unit/test_ai_prompts.py
git commit -m "feat(ai): update SYSTEM_ATTACK with library reference"
```

---

### Task 8: Remove old get_tools_list and get_workflows_list functions

**Files:**
- Modify: `secator/tasks/ai_prompts.py`
- Test: `tests/unit/test_ai_prompts.py`

**Step 1: Update tests to remove old function references**

Remove any tests that reference `get_tools_list` or `get_workflows_list`. Update the import in test file.

**Step 2: Run tests to verify current state**

Run: `python -m pytest tests/unit/test_ai_prompts.py -v`
Expected: PASS (no tests should reference removed functions)

**Step 3: Remove old functions**

Remove `get_tools_list()` and `get_workflows_list()` functions from `secator/tasks/ai_prompts.py` (they are no longer used).

**Step 4: Run all AI-related tests**

Run: `python -m pytest tests/unit/test_ai_prompts.py tests/unit/test_ai_handlers.py tests/unit/test_ai_actions.py -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add secator/tasks/ai_prompts.py tests/unit/test_ai_prompts.py
git commit -m "refactor(ai): remove unused get_tools_list and get_workflows_list"
```

---

### Task 9: Final verification and cleanup

**Files:**
- All AI-related files

**Step 1: Run full test suite**

Run: `python -m pytest tests/unit/test_ai*.py -v`
Expected: ALL PASS

**Step 2: Run linting**

Run: `secator test lint`
Expected: No new errors

**Step 3: Test manually**

Run: `secator x ai "scan example.com" --dry-run -v`
Verify: Prompt shows TASKS:, WORKFLOWS:, PROFILES:, etc.

**Step 4: Final commit**

```bash
git add -A
git commit -m "feat(ai): complete compact library reference implementation"
```
