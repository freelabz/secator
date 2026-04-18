# search_vulns Input Grouping Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Reduce redundant `search_vulns` subprocess calls in large scans by grouping hosts that share the same service/version into a single task input (`HOST1,HOST2~SERVICE VERSION`).

**Architecture:** Add a `group_by` field to the extractor system in `_helpers.py` that aggregates matched-at hosts by a key (the service/version string), producing one grouped input per unique service. `search_vulns.before_init` already parses the `~` separator; it just needs to handle comma-separated hosts. `on_json_loaded` fans the results out to each host.

**Tech Stack:** Python, unittest, secator extractor system (`_helpers.py`), YAML workflow config

---

## Context

The extractor system (`secator/runners/_helpers.py`) processes result objects and extracts values.
`parse_extractor` parses extractor dicts/strings into tuples. `process_extractor` filters results
by type/condition, then formats each matching item using `field`. The result is a flat list of strings.

`group_by` is a new optional extractor field. When set, items are bucketed by the `group_by`
template. Within each bucket, the part of `field` before `~` (the `matched_at` host) is joined
with `,`. This produces one output string per unique group key.

**How to run tests:**
```bash
source .venv/bin/activate
secator test unit --test test_runners_helpers
secator test unit --task search_vulns --test test_tasks
secator test lint
```

---

## Task 1: Extend `parse_extractor` to support `group_by`

**Files:**
- Modify: `secator/runners/_helpers.py:124-146`
- Test: `tests/unit/test_runners_helpers.py`

`parse_extractor` currently returns a 3-tuple `(_type, _field, _condition)`. We extend it to a
4-tuple by reading the optional `group_by` key from dict extractors.

**Step 1: Write the failing tests**

Add to `TestExtractorFunctions` in `tests/unit/test_runners_helpers.py`:

```python
def test_parse_extractor_dict_with_group_by(self):
    """Test parsing extractor dict with group_by field."""
    extractor = {
        'type': 'mock',
        'field': '{field1}~{field2}',
        'condition': 'item.field2 > 1',
        'group_by': '{field2}',
    }
    result = parse_extractor(extractor)
    self.assertEqual(result, ('mock', '{field1}~{field2}', 'item.field2 > 1', '{field2}'))

def test_parse_extractor_dict_without_group_by(self):
    """Test that group_by defaults to None when absent."""
    extractor = {'type': 'mock', 'field': 'field1'}
    result = parse_extractor(extractor)
    self.assertEqual(result, ('mock', 'field1', None, None))

def test_parse_extractor_string_no_group_by(self):
    """String format never has group_by."""
    result = parse_extractor('mock.field1')
    self.assertEqual(result, ('mock', 'field1', None, None))
```

**Step 2: Run tests to verify they fail**

```bash
source .venv/bin/activate
secator test unit --test test_runners_helpers
```

Expected: FAIL — `parse_extractor` still returns 3-tuple, so `assertEqual(..., (..., None))` fails.

**Step 3: Update `parse_extractor` in `secator/runners/_helpers.py`**

Replace the current function body:

```python
def parse_extractor(extractor):
    """Parse extractor.

    Args:
        extractor (dict / str): extractor definition.

    Returns:
        tuple|None: type, field, condition, group_by or None if invalid.
    """
    if isinstance(extractor, dict):
        _type = extractor['type']
        _field = extractor.get('field')
        _condition = extractor.get('condition')
        _group_by = extractor.get('group_by')
    else:
        parts = tuple(extractor.split('.'))
        if len(parts) == 2:
            _type = parts[0]
            _field = parts[1]
            _condition = None
            _group_by = None
        else:
            return None
    return _type, _field, _condition, _group_by
```

**Step 4: Fix all callers of `parse_extractor` that unpack the tuple**

`parse_extractor` is called in two places — update both to unpack 4 values:

In `fmt_extractor` (line ~77):
```python
# Before:
parsed_extractor = parse_extractor(extractor)
if not parsed_extractor:
    return '<DYNAMIC[INVALID_EXTRACTOR]>'
_type, _field, _condition = parsed_extractor

# After:
parsed_extractor = parse_extractor(extractor)
if not parsed_extractor:
    return '<DYNAMIC[INVALID_EXTRACTOR]>'
_type, _field, _condition, _group_by = parsed_extractor
```

In `process_extractor` (line ~165):
```python
# Before:
parsed_extractor = parse_extractor(extractor)
if not parsed_extractor:
    return results
_type, _field, _condition = parsed_extractor

# After:
parsed_extractor = parse_extractor(extractor)
if not parsed_extractor:
    return results
_type, _field, _condition, _group_by = parsed_extractor
```

**Step 5: Update existing `test_parse_extractor_string` and `test_parse_extractor_dict` tests**

The existing tests assert 3-tuples — update them to 4-tuples:

```python
def test_parse_extractor_string(self):
    result = parse_extractor('mock.field1')
    self.assertEqual(result, ('mock', 'field1', None, None))   # was (... None)

    result = parse_extractor('invalid_format')
    self.assertIsNone(result)

    result = parse_extractor('')
    self.assertIsNone(result)

def test_parse_extractor_dict(self):
    extractor = {'type': 'mock', 'field': 'field1', 'condition': 'item.field2 > 1'}
    result = parse_extractor(extractor)
    self.assertEqual(result, ('mock', 'field1', 'item.field2 > 1', None))  # was (... '1')

    extractor = {'type': 'mock'}
    result = parse_extractor(extractor)
    self.assertEqual(result, ('mock', None, None, None))  # was (... None)
```

**Step 6: Run tests to verify they pass**

```bash
secator test unit --test test_runners_helpers
```

Expected: all `TestExtractorFunctions` tests PASS.

**Step 7: Commit**

```bash
git add secator/runners/_helpers.py tests/unit/test_runners_helpers.py
git commit -m "feat: extend parse_extractor to support group_by field"
```

---

## Task 2: Implement `group_by` grouping in `process_extractor`

**Files:**
- Modify: `secator/runners/_helpers.py:149-207`
- Test: `tests/unit/test_runners_helpers.py`

When `_group_by` is set, after filtering and field-formatting, group items by the `group_by`
template. Items whose formatted `field` contains `~` have their prefix (before `~`) joined with
`,` per group key. Items without `~` are grouped by key and joined with `,`.

**Step 1: Write the failing tests**

Add to `TestExtractorFunctions`. First, add a richer mock type to `setUp` that mimics Technology:

```python
# In setUp, add:
from secator.output_types import Technology
self.tech1 = Technology(match='10.0.0.1:80', product='apache httpd', version='2.4.50')
self.tech2 = Technology(match='10.0.0.2:80', product='apache httpd', version='2.4.50')
self.tech3 = Technology(match='10.0.0.3:80', product='nginx', version='1.21.0')
self.tech_results = [self.tech1, self.tech2, self.tech3]
```

Then add tests:

```python
def test_process_extractor_group_by_combines_hosts(self):
    """group_by groups items by key and joins matched_at values with comma."""
    extractor = {
        'type': 'technology',
        'field': '{match}~{product} {version}',
        'condition': 'item.version',
        'group_by': '{product} {version}',
    }
    result = process_extractor(self.tech_results, extractor)
    self.assertEqual(len(result), 2)
    # Apache group: both hosts joined
    self.assertIn('10.0.0.1:80,10.0.0.2:80~apache httpd 2.4.50', result)
    # nginx group: single host
    self.assertIn('10.0.0.3:80~nginx 1.21.0', result)

def test_process_extractor_group_by_single_item(self):
    """group_by with one item per group produces normal ~ format."""
    extractor = {
        'type': 'technology',
        'field': '{match}~{product} {version}',
        'condition': 'item.version',
        'group_by': '{product} {version}',
    }
    result = process_extractor([self.tech3], extractor)
    self.assertEqual(result, ['10.0.0.3:80~nginx 1.21.0'])

def test_process_extractor_without_group_by_unchanged(self):
    """Without group_by, process_extractor behaves exactly as before."""
    extractor = {
        'type': 'technology',
        'field': '{match}~{product} {version}',
        'condition': 'item.version',
    }
    result = process_extractor(self.tech_results, extractor)
    self.assertEqual(len(result), 3)
    self.assertIn('10.0.0.1:80~apache httpd 2.4.50', result)
    self.assertIn('10.0.0.2:80~apache httpd 2.4.50', result)
    self.assertIn('10.0.0.3:80~nginx 1.21.0', result)
```

**Step 2: Run tests to verify they fail**

```bash
secator test unit --test test_runners_helpers
```

Expected: `test_process_extractor_group_by_*` FAIL — `process_extractor` ignores `group_by`.

**Step 3: Implement `group_by` in `process_extractor`**

In `secator/runners/_helpers.py`, add the grouping block at the end of `process_extractor`,
**after** the existing field-formatting block (line ~202-205) and **before** the return:

```python
    # Format field if needed
    if _field:
        already_formatted = '{' in _field and '}' in _field
        _field = '{' + _field + '}' if not already_formatted else _field
        results = [_field.format(**item.toDict()) for item in results]

    # Group results by group_by key if specified
    if _group_by:
        already_formatted = '{' in _group_by and '}' in _group_by
        _group_by = '{' + _group_by + '}' if not already_formatted else _group_by
        # Re-iterate over the pre-format results to build group keys
        # We need original items — recompute before field formatting
        # Restructure: compute keys and values together
        groups = {}
        for item in _pre_group_results:
            key = _group_by.format(**item.toDict())
            value = _field.format(**item.toDict())
            prefix = value.split('~')[0] if '~' in value else value
            groups.setdefault(key, []).append(prefix)
        results = [','.join(hosts) + '~' + key for key, hosts in groups.items()]

    return results
```

Wait — this requires keeping the original items before field-formatting. Restructure the end of
`process_extractor` as follows (replace from the `# Format field if needed` comment onward):

```python
    # Format field if needed
    if _field:
        already_formatted = '{' in _field and '}' in _field
        _field = '{' + _field + '}' if not already_formatted else _field

        # Group results by group_by key if specified
        if _group_by:
            already_formatted_gb = '{' in _group_by and '}' in _group_by
            _group_by = '{' + _group_by + '}' if not already_formatted_gb else _group_by
            groups = {}
            for item in results:
                key = _group_by.format(**item.toDict())
                value = _field.format(**item.toDict())
                prefix = value.split('~')[0] if '~' in value else value
                groups.setdefault(key, []).append(prefix)
            results = [','.join(hosts) + '~' + key for key, hosts in groups.items()]
        else:
            results = [_field.format(**item.toDict()) for item in results]

    # debug('after extract', ...)
    return results
```

Note: `results` at this point is still a list of OutputType objects (not yet formatted strings),
so iterating over items and calling `.toDict()` is valid.

**Step 4: Run tests to verify they pass**

```bash
secator test unit --test test_runners_helpers
```

Expected: all tests PASS including the new `group_by` tests.

**Step 5: Lint check**

```bash
secator test lint
```

Expected: no new lint errors.

**Step 6: Commit**

```bash
git add secator/runners/_helpers.py tests/unit/test_runners_helpers.py
git commit -m "feat: implement group_by in process_extractor to aggregate matched_at by key"
```

---

## Task 3: Handle comma-separated `matched_at` in `search_vulns`

**Files:**
- Modify: `secator/tasks/search_vulns.py:56-66` (before_init), `secator/tasks/search_vulns.py:68-164` (on_json_loaded)
- Test: `tests/unit/test_tasks.py`

`before_init` already splits `~` and sets `self.matched_at` to the prefix. With grouping,
`self.matched_at` is now e.g. `"10.0.0.1:80,10.0.0.2:80"`. No change needed to `before_init`.

`on_json_loaded` currently uses `matched_at` as a single string for every Vulnerability/Exploit
it emits. We change it to split on `,` and emit one object per host.

**Step 1: Read the current test_tasks.py to understand task test patterns**

```bash
grep -n "search_vulns\|before_init\|matched_at" tests/unit/test_tasks.py | head -30
```

**Step 2: Write the failing tests**

Find the search_vulns section in `tests/unit/test_tasks.py` and add:

```python
import json
import os

class TestSearchVulnsGrouping(unittest.TestCase):

    def _load_fixture(self):
        fixture_path = os.path.join(
            os.path.dirname(__file__), '..', 'fixtures', 'search_vulns_output.json'
        )
        with open(fixture_path) as f:
            return json.load(f)

    def test_before_init_single_host(self):
        """before_init parses single host from matched_at~service format."""
        task = search_vulns.__new__(search_vulns)
        task.inputs = ['10.0.0.1:80~apache 2.4.39']
        task.matched_at = None
        search_vulns.before_init(task)
        self.assertEqual(task.matched_at, '10.0.0.1:80')
        self.assertEqual(task.inputs[0], 'apache 2.4.39')

    def test_before_init_multiple_hosts(self):
        """before_init correctly captures comma-separated matched_at hosts."""
        task = search_vulns.__new__(search_vulns)
        task.inputs = ['10.0.0.1:80,10.0.0.2:80~apache 2.4.39']
        task.matched_at = None
        search_vulns.before_init(task)
        self.assertEqual(task.matched_at, '10.0.0.1:80,10.0.0.2:80')
        self.assertEqual(task.inputs[0], 'apache 2.4.39')

    def test_on_json_loaded_single_host_emits_one_vuln(self):
        """on_json_loaded with single matched_at emits one Vulnerability per CVE."""
        fixture = self._load_fixture()
        task = search_vulns.__new__(search_vulns)
        task.inputs = ['apache 2.4.39']
        task.matched_at = '10.0.0.1:80'
        task.run_opts = {}

        vulns = []
        for data in fixture.items():
            item = dict([data])
            for result in search_vulns.on_json_loaded(task, item):
                if isinstance(result, Vulnerability):
                    vulns.append(result)
            break  # one fixture entry is enough

        # Each CVE in the fixture should yield exactly 1 Vulnerability for the 1 host
        cve_count = len(list(fixture.values())[0].get('vulns', {}))
        self.assertEqual(len(vulns), cve_count)
        for v in vulns:
            self.assertEqual(v.matched_at, '10.0.0.1:80')

    def test_on_json_loaded_multiple_hosts_emits_vuln_per_host(self):
        """on_json_loaded with comma-separated matched_at emits one Vulnerability per host per CVE."""
        fixture = self._load_fixture()
        task = search_vulns.__new__(search_vulns)
        task.inputs = ['apache 2.4.39']
        task.matched_at = '10.0.0.1:80,10.0.0.2:80'
        task.run_opts = {}

        vulns = []
        for data in fixture.items():
            item = dict([data])
            for result in search_vulns.on_json_loaded(task, item):
                if isinstance(result, Vulnerability):
                    vulns.append(result)
            break

        cve_count = len(list(fixture.values())[0].get('vulns', {}))
        # 2 hosts × N CVEs = 2N vulnerabilities
        self.assertEqual(len(vulns), cve_count * 2)
        matched_ats = {v.matched_at for v in vulns}
        self.assertEqual(matched_ats, {'10.0.0.1:80', '10.0.0.2:80'})
```

**Step 3: Run tests to verify they fail**

```bash
secator test unit --test test_tasks
```

Expected: `test_on_json_loaded_multiple_hosts_emits_vuln_per_host` FAIL — currently emits
one Vulnerability with `matched_at = '10.0.0.1:80,10.0.0.2:80'` (not split).

**Step 4: Update `on_json_loaded` in `secator/tasks/search_vulns.py`**

Change the matched_at resolution at the top of `on_json_loaded` and update both Vulnerability
and Exploit emission to loop over hosts:

```python
@staticmethod
def on_json_loaded(self, item):
    """Load vulnerability items from search_vulns JSON output."""
    matched_at_raw = self.matched_at if self.matched_at else self.inputs[0] if self.inputs else ''
    matched_ats = matched_at_raw.split(',') if matched_at_raw else ['']

    values = item.values()
    if not values:
        return None

    data = list(values)[0]
    if isinstance(data, str):
        yield Warning(message=data.replace('Warning: ', ''))
        return

    vulns = data.get('vulns', {})
    common_extra_data = {}

    for cve_id, vuln_data in vulns.items():
        match_reason = vuln_data.get('match_reason', '')
        confidence = 'high'
        tags = search_vulns.extract_tags(vuln_data)
        exploits = vuln_data.get('exploits', [])
        cvss_score = float(vuln_data.get('cvss', 0))
        extra_data = search_vulns.extract_extra_data(vuln_data)
        references = search_vulns.extract_references(vuln_data)

        # Build base vuln data (without matched_at)
        base_data = {
            'id': cve_id,
            'name': cve_id,
            'description': vuln_data.get('description', ''),
            'confidence': confidence,
            'cvss_score': cvss_score,
            'epss_score': vuln_data.get('epss', ''),
            'cvss_vec': vuln_data.get('cvss_vec', ''),
            'references': references,
            'extra_data': extra_data,
            'provider': 'search_vulns',
            'tags': tags,
        }
        if int(cvss_score) == 0:
            vuln = Vuln.lookup_cve(cve_id)
            if vuln:
                base_data.update(vuln.toDict())
                base_data['confidence'] = confidence
                base_data['references'] = references + base_data.get('references', [])
                base_data['extra_data'].update(extra_data)

        if match_reason == 'general_product_uncertain':
            base_data['confidence'] = 'low'
            base_data['tags'].append('uncertain')
        if len(exploits) > 0:
            base_data['tags'].append('exploitable')

        # Emit one Vulnerability per matched_at host
        for matched_at in matched_ats:
            yield Vulnerability(**{**base_data, 'matched_at': matched_at})

        # Exploits
        if len(exploits) > 2:
            yield Info(message=f'{len(exploits)} exploits found. Keeping max 3')
            exploits = exploits[:3]
        for exploit in exploits:
            extra_data = common_extra_data.copy()
            parts = exploit.replace('http://', '').replace('https://', '').replace('github.com', 'github').split('/')
            hostname = urlparse(exploit).hostname
            tags = [hostname]
            provider = hostname.split('.')[-2]
            is_github = 'github.com' in exploit
            if is_github:
                user = parts[1]
                repo = parts[2]
                name = 'Github'
                extra_data.update({'user': user, 'repo': repo})
            else:
                hostname = urlparse(exploit).hostname
                name = provider.capitalize()
            name = name + ' exploit'
            last_part = exploit.split('/')[-1]
            id = f'{cve_id}-exploit'
            if last_part.isnumeric():
                id = last_part
                name += f' {id}'
            # Emit one Exploit per matched_at host
            for matched_at in matched_ats:
                yield Exploit(
                    name=name,
                    provider=provider,
                    id=id,
                    matched_at=matched_at,
                    confidence=confidence,
                    reference=exploit,
                    cves=[cve_id],
                    tags=tags,
                    extra_data=extra_data,
                )
```

**Step 5: Run tests to verify they pass**

```bash
secator test unit --test test_tasks
```

Expected: all `TestSearchVulnsGrouping` tests PASS.

**Step 6: Lint check**

```bash
secator test lint
```

**Step 7: Commit**

```bash
git add secator/tasks/search_vulns.py tests/unit/test_tasks.py
git commit -m "feat: fan out search_vulns results to multiple matched_at hosts"
```

---

## Task 4: Add `group_by` to `host_recon.yaml`

**Files:**
- Modify: `secator/configs/workflows/host_recon.yaml:98-119`

Add `group_by: '{product} {version}'` to the technology extractor for both `search_vulns` and
`searchsploit`.

**Step 1: Edit `host_recon.yaml`**

Change the `_group/vuln` section from:

```yaml
  _group/vuln:
    searchsploit:
      description: Search for related exploits
      targets_:
        - type: vulnerability
          field: '{matched_at}~{id}'
          condition: item.id
        - type: technology
          field: '{match}~{product} {version}'
          condition: item.version
      if: "'searchsploit' in opts.exploiters"

    search_vulns:
      description: Search for related vulns and exploits
      targets_:
        - type: vulnerability
          field: '{matched_at}~{id}'
          condition: item.id
        - type: technology
          field: '{match}~{product} {version}'
          condition: item.version
      if: "'search_vulns' in opts.exploiters"
```

To:

```yaml
  _group/vuln:
    searchsploit:
      description: Search for related exploits
      targets_:
        - type: vulnerability
          field: '{matched_at}~{id}'
          condition: item.id
        - type: technology
          field: '{match}~{product} {version}'
          condition: item.version
          group_by: '{product} {version}'
      if: "'searchsploit' in opts.exploiters"

    search_vulns:
      description: Search for related vulns and exploits
      targets_:
        - type: vulnerability
          field: '{matched_at}~{id}'
          condition: item.id
        - type: technology
          field: '{match}~{product} {version}'
          condition: item.version
          group_by: '{product} {version}'
      if: "'search_vulns' in opts.exploiters"
```

**Step 2: Verify the YAML loads without error**

```bash
source .venv/bin/activate
python -c "from secator.loader import get_configs_by_type; cfgs = get_configs_by_type('workflow'); print([c.name for c in cfgs])"
```

Expected: list of workflow names including `host_recon`, no exceptions.

**Step 3: Dry-run the workflow to verify extractor output**

```bash
secator w host_recon 127.0.0.1 --dry-run 2>&1 | head -40
```

Expected: no errors; workflow prints task tree.

**Step 4: Run unit tests to confirm nothing regressed**

```bash
secator test unit
```

Expected: all tests PASS.

**Step 5: Lint check**

```bash
secator test lint
```

**Step 6: Commit**

```bash
git add secator/configs/workflows/host_recon.yaml
git commit -m "feat: group search_vulns and searchsploit inputs by service/version in host_recon"
```

---

## Task 5: End-to-end smoke test with mock data

**Files:**
- Test: `tests/unit/test_runners_helpers.py` (add integration-style test using Technology objects)

Verify the full pipeline: extractor grouping → single task input → fanned-out results.

**Step 1: Write the smoke test**

Add to `tests/unit/test_runners_helpers.py`:

```python
def test_run_extractors_with_group_by(self):
    """Full pipeline: Technology items → grouped search_vulns inputs via group_by extractor."""
    from secator.output_types import Technology

    tech1 = Technology(match='10.0.0.1:80', product='apache httpd', version='2.4.50')
    tech2 = Technology(match='10.0.0.2:80', product='apache httpd', version='2.4.50')
    tech3 = Technology(match='10.0.0.3:80', product='nginx', version='1.21.0')
    results = [tech1, tech2, tech3]

    opts = {
        'targets_': [
            {
                'type': 'technology',
                'field': '{match}~{product} {version}',
                'condition': 'item.version',
                'group_by': '{product} {version}',
            }
        ]
    }

    inputs, updated_opts, errors = run_extractors(results, opts)
    self.assertEqual(errors, [])
    self.assertEqual(len(inputs), 2)  # 2 unique services
    # Apache: both hosts grouped
    apache_input = next(i for i in inputs if 'apache' in i)
    self.assertIn('10.0.0.1:80', apache_input.split('~')[0])
    self.assertIn('10.0.0.2:80', apache_input.split('~')[0])
    self.assertEqual(apache_input.split('~')[1], 'apache httpd 2.4.50')
    # nginx: single host
    nginx_input = next(i for i in inputs if 'nginx' in i)
    self.assertEqual(nginx_input, '10.0.0.3:80~nginx 1.21.0')
```

**Step 2: Run the smoke test**

```bash
secator test unit --test test_runners_helpers
```

Expected: PASS.

**Step 3: Run full unit suite one final time**

```bash
secator test unit
secator test lint
```

Expected: all PASS, no lint errors.

**Step 4: Commit**

```bash
git add tests/unit/test_runners_helpers.py
git commit -m "test: add end-to-end smoke test for group_by extractor pipeline"
```

---

## Summary of commits

| Commit | Files |
|--------|-------|
| `feat: extend parse_extractor to support group_by field` | `_helpers.py`, `test_runners_helpers.py` |
| `feat: implement group_by in process_extractor` | `_helpers.py`, `test_runners_helpers.py` |
| `feat: fan out search_vulns results to multiple matched_at hosts` | `search_vulns.py`, `test_tasks.py` |
| `feat: group search_vulns inputs by service/version in host_recon` | `host_recon.yaml` |
| `test: end-to-end smoke test for group_by extractor pipeline` | `test_runners_helpers.py` |
